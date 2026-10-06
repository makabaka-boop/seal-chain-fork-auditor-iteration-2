package audit_test

import (
	"encoding/hex"
	"math/rand"
	"strings"
	"testing"

	"sealaudit/internal/audit"
)

// Pinned vectors for the receiving museum's batch. They were independently
// computed over the signed byte layout with v3's digest as h0's previous
// digest:
//
//	h0 -> f0309276c4cd9989ec1d9d6a0b1c92e2efbe51a88a1684f4559f8c332e4a5eea
//	h1 -> a3592824bce426abfb8e53fb2f94635d152f5582e29c457f1ca6e3e0e007dd0d
var pinnedHandoffChain = []struct {
	id, payload, prevDigest, digest string
}{
	{"h0", "hand-0", "caebe7a58c8339810ebe10bab9f1b8765a241ae1315a9e1dea4a27c04ea2be9e", "f0309276c4cd9989ec1d9d6a0b1c92e2efbe51a88a1684f4559f8c332e4a5eea"},
	{"h1", "hand-1", "f0309276c4cd9989ec1d9d6a0b1c92e2efbe51a88a1684f4559f8c332e4a5eea", "a3592824bce426abfb8e53fb2f94635d152f5582e29c457f1ca6e3e0e007dd0d"},
}

func handoffFromPinned(t *testing.T, hiddenFirst, hiddenSecond map[string]bool, perm ...int) ([]audit.LimitedEvent, []audit.LimitedEvent) {
	t.Helper()
	first := limitedFromPinned(t, hiddenFirst)
	order := perm
	if order == nil {
		order = []int{0, 1}
	}
	second := make([]audit.LimitedEvent, len(order))
	for pos, i := range order {
		v := pinnedHandoffChain[i]
		le := audit.LimitedEvent{
			Event: audit.Event{
				ID:         v.id,
				ParentID:   "",
				PrevDigest: v.prevDigest,
				Digest:     v.digest,
			},
			Disclosed: !hiddenSecond[v.id],
		}
		if i > 0 {
			le.ParentID = pinnedHandoffChain[i-1].id
		}
		if le.Disclosed {
			le.Payload = v.payload
		} else {
			le.Payload = "WITHHELD-HANDOFF-BODY-MUST-NOT-LEAK-" + v.id
		}
		second[pos] = le
	}
	return first, second
}

func TestHandoffAllDisclosedVerifiedAndOrderIndependent(t *testing.T) {
	r := rand.New(rand.NewSource(20261006))
	wantIDs := []string{"v0", "v1", "v2", "v3", "h0", "h1"}
	wantStatus := []audit.EventStatus{
		audit.StatusVerified, audit.StatusVerified, audit.StatusVerified,
		audit.StatusVerified, audit.StatusVerified, audit.StatusVerified,
	}

	for iter := 0; iter < 50; iter++ {
		first, second := handoffFromPinned(t, nil, nil, 0, 1)
		rep := audit.AuditLimitedHandoff(
			shuffledLimitedCopy(t, first, r),
			shuffledLimitedCopy(t, second, r),
		)
		if !rep.Valid || rep.Status != audit.ChainVerified {
			t.Fatalf("iter %d: want valid/VERIFIED, got %#v errors=%#v", iter, rep, rep.Errors)
		}
		if len(rep.Events) != len(wantIDs) {
			t.Fatalf("iter %d: got %d events, want %d", iter, len(rep.Events), len(wantIDs))
		}
		for i, e := range rep.Events {
			if e.ID != wantIDs[i] {
				t.Fatalf("iter %d: position %d = %s, want %s", iter, i, e.ID, wantIDs[i])
			}
			if e.Status != wantStatus[i] {
				t.Fatalf("iter %d: %s status = %s, want %s", iter, e.ID, e.Status, wantStatus[i])
			}
		}
		if rep.TailDigest != pinnedHandoffChain[1].digest {
			t.Fatalf("iter %d: tail = %s", iter, rep.TailDigest)
		}
	}
}

func TestHandoffAnchorMismatch(t *testing.T) {
	first, second := handoffFromPinned(t, nil, nil)
	for i := range second {
		if second[i].ID == "h0" {
			// Keep h0's own digest internally consistent with the fake anchor,
			// isolating the cross-batch link defect from an own-digest defect.
			fakeRaw := mustHashRaw(mustHex(strings.Repeat("f", 64)))
			second[i].PrevDigest = strings.Repeat("f", 64)
			second[i].Digest = audit.ComputeDigest("h0", "hand-0", fakeRaw)
		}
	}

	rep := audit.AuditLimitedHandoff(first, second)
	if rep.Valid || rep.Events != nil || rep.TailDigest != "" {
		t.Fatalf("handoff mismatch must return only errors, got %#v", rep)
	}
	if !hasError(rep.Errors, audit.ErrHandoffDigestMismatch, "h0") {
		t.Fatalf("want HANDOFF_DIGEST_MISMATCH/h0, got %#v", rep.Errors)
	}
}

func TestHandoffZeroAnchorUsesHandoffCode(t *testing.T) {
	first, second := handoffFromPinned(t, nil, nil)
	for i := range second {
		if second[i].ID == "h0" {
			var zero [32]byte
			second[i].PrevDigest = audit.ZeroDigest
			second[i].Digest = audit.ComputeDigest("h0", "hand-0", zero)
		}
	}

	rep := audit.AuditLimitedHandoff(first, second)
	if !hasError(rep.Errors, audit.ErrHandoffDigestMismatch, "h0") {
		t.Fatalf("second-batch zero anchor must be a handoff error, got %#v", rep.Errors)
	}
	if hasError(rep.Errors, audit.ErrRootPrevDigestNotZero, "h0") {
		t.Fatalf("second root must not use the first-batch root code: %#v", rep.Errors)
	}
}

func TestHandoffBrokenIntraBatchLink(t *testing.T) {
	first, second := handoffFromPinned(t, nil, nil)
	for i := range second {
		if second[i].ID == "h1" {
			fakeRaw := mustHashRaw(mustHex(strings.Repeat("e", 64)))
			second[i].PrevDigest = strings.Repeat("e", 64)
			second[i].Digest = audit.ComputeDigest("h1", "hand-1", fakeRaw)
		}
	}

	rep := audit.AuditLimitedHandoff(first, second)
	if rep.Valid {
		t.Fatal("broken second-batch link must invalidate handoff")
	}
	if !hasError(rep.Errors, audit.ErrPrevDigestMismatch, "h1") {
		t.Fatalf("want PREV_DIGEST_MISMATCH/h1, got %#v", rep.Errors)
	}
}

func TestHandoffCrossBatchDuplicateID(t *testing.T) {
	first, second := handoffFromPinned(t, nil, nil)
	for i := range second {
		if second[i].ID == "h1" {
			second[i].ID = "v3"
		}
	}

	rep := audit.AuditLimitedHandoff(first, second)
	if rep.Valid || rep.Events != nil {
		t.Fatalf("cross-batch duplicate must suppress the concatenated chain, got %#v", rep)
	}
	if !hasError(rep.Errors, audit.ErrCrossBatchDuplicateID, "v3") {
		t.Fatalf("want CROSS_BATCH_DUPLICATE_ID/v3, got %#v", rep.Errors)
	}
}

func TestHandoffFirstBatchInvalidStillChecksSecondBatch(t *testing.T) {
	first, second := handoffFromPinned(t, nil, nil)
	for i := range first {
		if first[i].ID == "v2" {
			first[i].Payload = "tampered"
		}
	}
	for i := range second {
		if second[i].ID == "h1" {
			second[i].PrevDigest = strings.Repeat("c", 64)
		}
	}

	rep := audit.AuditLimitedHandoff(first, second)
	if rep.Valid {
		t.Fatal("want invalid report")
	}
	if !hasError(rep.Errors, audit.ErrDigestMismatch, "v2") {
		t.Fatalf("first batch must be checked, got %#v", rep.Errors)
	}
	if !hasError(rep.Errors, audit.ErrPrevDigestMismatch, "h1") {
		t.Fatalf("second batch checks must run alongside first-batch checks, got %#v", rep.Errors)
	}
}

func TestHandoffFirstHiddenTrustPropagation(t *testing.T) {
	first, second := handoffFromPinned(t, map[string]bool{"v1": true}, nil)
	rep := audit.AuditLimitedHandoff(first, second)
	if !rep.Valid || rep.Status != audit.ChainPartial {
		t.Fatalf("want valid/PARTIAL, got %#v errors=%#v", rep, rep.Errors)
	}
	want := []audit.EventStatus{
		audit.StatusVerifiedPrefix,
		audit.StatusAnchorUnverified,
		audit.StatusAnchorUnverified,
		audit.StatusAnchorUnverified,
		audit.StatusAnchorUnverified,
		audit.StatusAnchorUnverified,
	}
	if got := handoffStatuses(rep); !equalStatuses(got, want) {
		t.Fatalf("first-batch hidden propagation: %v want %v", got, want)
	}
}

func TestHandoffSecondHiddenTrustPropagation(t *testing.T) {
	first, second := handoffFromPinned(t, nil, map[string]bool{"h0": true})
	rep := audit.AuditLimitedHandoff(first, second)
	if !rep.Valid || rep.Status != audit.ChainPartial {
		t.Fatalf("want valid/PARTIAL, got %#v", rep)
	}
	want := []audit.EventStatus{
		audit.StatusVerifiedPrefix,
		audit.StatusVerifiedPrefix,
		audit.StatusVerifiedPrefix,
		audit.StatusVerifiedPrefix,
		audit.StatusAnchorUnverified,
		audit.StatusAnchorUnverified,
	}
	if got := handoffStatuses(rep); !equalStatuses(got, want) {
		t.Fatalf("second-batch hidden statuses: %v want %v", got, want)
	}
	if p, ok := handoffPayload(rep, "h0"); ok || p != nil {
		t.Fatalf("hidden h0 payload leaked: %v", p)
	}
}

func TestHandoffAnchorCheckUsesRebuiltFirstTailWhenHidden(t *testing.T) {
	first, second := handoffFromPinned(t, map[string]bool{"v3": true}, nil)
	for i := range second {
		if second[i].ID == "h0" {
			fakeRaw := mustHashRaw(mustHex(strings.Repeat("a", 64)))
			second[i].PrevDigest = strings.Repeat("a", 64)
			second[i].Digest = audit.ComputeDigest("h0", "hand-0", fakeRaw)
		}
	}
	rep := audit.AuditLimitedHandoff(first, second)
	if rep.Valid {
		t.Fatal("anchor mismatch with hidden first tail must still be rejected")
	}
	if !hasError(rep.Errors, audit.ErrHandoffDigestMismatch, "h0") {
		t.Fatalf("want handoff mismatch against declared rebuilt tail, got %#v", rep.Errors)
	}
}

func TestHandoffErrorsSorted(t *testing.T) {
	first, second := handoffFromPinned(t, nil, nil)
	for i := range first {
		if first[i].ID == "v2" {
			first[i].Payload = "tampered"
		}
	}
	for i := range second {
		switch second[i].ID {
		case "h0":
			second[i].PrevDigest = strings.Repeat("b", 64)
		case "h1":
			second[i].ID = "v2"
		}
	}
	rep := audit.AuditLimitedHandoff(first, second)
	for i := 1; i < len(rep.Errors); i++ {
		a, b := rep.Errors[i-1], rep.Errors[i]
		if a.Code > b.Code || (a.Code == b.Code && a.EventID > b.EventID) {
			t.Fatalf("errors not sorted: %#v before %#v; all=%#v", a, b, rep.Errors)
		}
	}
}

func TestHandoffRawSecondVectors(t *testing.T) {
	// Independently verify the pinned handoff digests, rather than trusting
	// ComputeDigest during vector construction.
	prev := mustHashRaw(mustHex(pinnedLimitedChain[3].digest))
	for _, v := range pinnedHandoffChain {
		got := audit.ComputeDigest(v.id, v.payload, prev)
		if got != v.digest {
			t.Fatalf("%s digest = %s, want pinned %s", v.id, got, v.digest)
		}
		raw, err := hex.DecodeString(v.digest)
		if err != nil {
			t.Fatal(err)
		}
		copy(prev[:], raw)
	}
}

func handoffStatuses(rep audit.LimitedReport) []audit.EventStatus {
	out := make([]audit.EventStatus, len(rep.Events))
	for i, e := range rep.Events {
		out[i] = e.Status
	}
	return out
}

func handoffPayload(rep audit.LimitedReport, id string) (*string, bool) {
	for _, e := range rep.Events {
		if e.ID == id {
			return e.Payload, e.Payload != nil
		}
	}
	return nil, false
}
