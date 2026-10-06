package audit_test

import (
	"encoding/hex"
	"encoding/json"
	"math/rand"
	"strings"
	"testing"

	"sealaudit/internal/audit"
)

// Pinned vectors for the dual-batch handoff chain, computed independently of
// production code (Python, SHA-256 over the spec buffer) for ids h0..h3,
// payloads handoff-0..handoff-3:
//
//	h0 root -> 87a00f7a3c50463eacf0994c92e24a125d00195586e910b02ed8a3af13e7efaa
//	h1      -> e85518ae3aebdaa8d6a6f30b14d114eb300ee2707a46e9e4aaf1ea1d36350fc4
//	h2      -> 741832b4b8e4b6846ca8a55b7abdcbb68ce68e5abd853b857adadc20b9226a6c
//	h3 tail -> 65c676c54e657a22739ff531985f275401e3be502ee71624855ece85a72c10c5
//
// The handoff split is after h1: batch 1 is [h0,h1] and batch 2 is [h2,h3].
// h2 is batch 2's root (no in-batch parentId) and its prevDigest is batch 1's
// rebuilt tail (h1). The tests build from these pinned digests rather than
// from ComputeDigest, so a changed digest definition breaks them outright.
var pinnedHandoffChain = []struct {
	id, payload, prevDigest, digest string
}{
	{"h0", "handoff-0", audit.ZeroDigest, "87a00f7a3c50463eacf0994c92e24a125d00195586e910b02ed8a3af13e7efaa"},
	{"h1", "handoff-1", "87a00f7a3c50463eacf0994c92e24a125d00195586e910b02ed8a3af13e7efaa", "e85518ae3aebdaa8d6a6f30b14d114eb300ee2707a46e9e4aaf1ea1d36350fc4"},
	{"h2", "handoff-2", "e85518ae3aebdaa8d6a6f30b14d114eb300ee2707a46e9e4aaf1ea1d36350fc4", "741832b4b8e4b6846ca8a55b7abdcbb68ce68e5abd853b857adadc20b9226a6c"},
	{"h3", "handoff-3", "741832b4b8e4b6846ca8a55b7abdcbb68ce68e5abd853b857adadc20b9226a6c", "65c676c54e657a22739ff531985f275401e3be502ee71624855ece85a72c10c5"},
}

const handoffSplit = 2 // batch 1 = h0,h1 ; batch 2 = h2,h3

// handoffFromPinned assembles the two batches from the pinned vectors.
// hidden lists withheld ids; perm (when non-nil) gives the upload order of
// global indices inside each batch, so events may arrive shuffled while the
// graph rebuild must still produce h0..h3. Hidden payloads are sentinel
// strings that must never appear in any output.
func handoffFromPinned(t *testing.T, hidden map[string]bool, firstPerm, secondPerm []int) audit.HandoffBatches {
	t.Helper()
	build := func(perm []int) []audit.HandoffEvent {
		out := make([]audit.HandoffEvent, len(perm))
		for pos, i := range perm {
			v := pinnedHandoffChain[i]
			le := audit.HandoffEvent{
				Event: audit.Event{
					ID:         v.id,
					ParentID:   "",
					PrevDigest: v.prevDigest,
					Digest:     v.digest,
				},
				Disclosed: !hidden[v.id],
			}
			// The first event of each batch is its root; every other event
			// links to its pinned predecessor.
			if i != 0 && i != handoffSplit {
				le.ParentID = pinnedHandoffChain[i-1].id
			}
			if le.Disclosed {
				le.Payload = v.payload
			} else {
				le.Payload = "WITHHELD-BODY-MUST-NOT-LEAK-" + v.id
			}
			out[pos] = le
		}
		return out
	}
	return audit.HandoffBatches{
		FirstBatch:  build(firstPerm),
		SecondBatch: build(secondPerm),
	}
}

func identityPerm(indices ...int) []int { return indices }

func shuffledHandoffCopy(t *testing.T, in audit.HandoffBatches, r *rand.Rand) audit.HandoffBatches {
	t.Helper()
	out := audit.HandoffBatches{
		FirstBatch:  append([]audit.HandoffEvent(nil), in.FirstBatch...),
		SecondBatch: append([]audit.HandoffEvent(nil), in.SecondBatch...),
	}
	r.Shuffle(len(out.FirstBatch), func(i, j int) {
		out.FirstBatch[i], out.FirstBatch[j] = out.FirstBatch[j], out.FirstBatch[i]
	})
	r.Shuffle(len(out.SecondBatch), func(i, j int) {
		out.SecondBatch[i], out.SecondBatch[j] = out.SecondBatch[j], out.SecondBatch[i]
	})
	return out
}

func handoffIDs(rep audit.HandoffReport) []string {
	out := make([]string, len(rep.Events))
	for i, e := range rep.Events {
		out[i] = e.ID
	}
	return out
}

// TestHandoffValidOrderIndependent is the headline handoff property: both
// batches uploaded in arbitrary order must splice into h0..h3 with batch 2's
// root anchored on batch 1's rebuilt tail, and the chain is VERIFIED only
// because every body was disclosed and recomputed end to end.
func TestHandoffValidOrderIndependent(t *testing.T) {
	r := rand.New(rand.NewSource(20261006))
	wantIDs := []string{"h0", "h1", "h2", "h3"}
	wantTail := pinnedHandoffChain[3].digest

	for iter := 0; iter < 50; iter++ {
		batches := shuffledHandoffCopy(t, handoffFromPinned(t, nil,
			identityPerm(0, 1), identityPerm(2, 3)), r)
		rep := audit.AuditHandoff(batches)
		if !rep.Valid || rep.Status != audit.ChainVerified {
			t.Fatalf("iter %d: want valid/VERIFIED, got %#v errors=%#v", iter, rep, rep.Errors)
		}
		if got := handoffIDs(rep); len(got) != 4 || got[0] != wantIDs[0] || got[1] != wantIDs[1] ||
			got[2] != wantIDs[2] || got[3] != wantIDs[3] {
			t.Fatalf("iter %d: rebuilt %v, want %v (graph rebuild, not upload order)", iter, got, wantIDs)
		}
		for i, e := range rep.Events {
			if e.Status != audit.StatusVerified {
				t.Fatalf("iter %d: %s status %s, want VERIFIED", iter, e.ID, e.Status)
			}
			if e.Payload == nil || *e.Payload != pinnedHandoffChain[i].payload {
				t.Fatalf("iter %d: %s payload not echoed as disclosed", iter, e.ID)
			}
		}
		if rep.TailDigest != wantTail {
			t.Fatalf("iter %d: tailDigest %s, want %s", iter, rep.TailDigest, wantTail)
		}
	}
}

// TestHandoffAnchorMismatch isolates the new handoff rule: batch 2 is a single
// internally consistent root whose prevDigest is not batch 1's rebuilt tail.
// Recomputing its own digest over the fake anchor proves the failure is purely
// the handoff anchor, not body tampering.
func TestHandoffAnchorMismatch(t *testing.T) {
	t.Run("nonzero foreign anchor", func(t *testing.T) {
		batches := handoffFromPinned(t, nil, identityPerm(0, 1), nil)
		var fake [32]byte
		for i := range fake {
			fake[i] = 0x11
		}
		fakeHex := hex.EncodeToString(fake[:])
		batches.SecondBatch = []audit.HandoffEvent{{
			Event: audit.Event{
				ID:         "h2",
				ParentID:   "",
				Payload:    "handoff-2",
				PrevDigest: fakeHex,
				Digest:     audit.ComputeDigest("h2", "handoff-2", fake),
			},
			Disclosed: true,
		}}
		rep := audit.AuditHandoff(batches)
		if rep.Valid || rep.Events != nil || rep.TailDigest != "" || rep.Status != "" {
			t.Fatalf("anchor mismatch must yield errors only, got %#v", rep)
		}
		codes := codesOf(rep.Errors)
		if got := codes[audit.ErrHandoffAnchorMismatch]; len(got) != 1 || got[0] != "h2" {
			t.Fatalf("want one HANDOFF_ANCHOR_MISMATCH on h2, got %#v", rep.Errors)
		}
		if len(codes) != 1 {
			t.Fatalf("internally consistent wrong anchor must yield only the handoff error, got %#v", rep.Errors)
		}
	})

	t.Run("all-zero anchor on second root", func(t *testing.T) {
		// A zero prevDigest on batch 2's root is not the zero-anchor rule
		// (which only applies to batch 1): with a nonzero first tail it is a
		// handoff anchor mismatch.
		batches := handoffFromPinned(t, nil, identityPerm(0, 1), nil)
		batches.SecondBatch = []audit.HandoffEvent{{
			Event: audit.Event{
				ID:         "h2",
				ParentID:   "",
				Payload:    "handoff-2",
				PrevDigest: audit.ZeroDigest,
				Digest:     audit.ComputeDigest("h2", "handoff-2", [32]byte{}),
			},
			Disclosed: true,
		}}
		rep := audit.AuditHandoff(batches)
		if !hasError(rep.Errors, audit.ErrHandoffAnchorMismatch, "h2") {
			t.Fatalf("want HANDOFF_ANCHOR_MISMATCH on h2, got %#v", rep.Errors)
		}
		if hasError(rep.Errors, audit.ErrRootPrevDigestNotZero, "h2") {
			t.Fatalf("the zero-anchor rule must not apply to batch 2's root, got %#v", rep.Errors)
		}
	})
}

// TestHandoffFirstBatchStillZeroAnchored: batch 1 keeps the original in-batch
// root rule; a nonzero root prevDigest there is ROOT_PREV_DIGEST_NOT_ZERO.
func TestHandoffFirstBatchStillZeroAnchored(t *testing.T) {
	batches := handoffFromPinned(t, nil, identityPerm(0, 1), identityPerm(2, 3))
	var one [32]byte
	for i := range one {
		one[i] = 0x01
	}
	for i := range batches.FirstBatch {
		if batches.FirstBatch[i].ID == "h0" {
			batches.FirstBatch[i].PrevDigest = hex.EncodeToString(one[:])
			batches.FirstBatch[i].Digest = audit.ComputeDigest("h0", "handoff-0", one)
		}
	}
	rep := audit.AuditHandoff(batches)
	if rep.Valid {
		t.Fatal("first-batch root anchor violation must reject the handoff")
	}
	if !hasError(rep.Errors, audit.ErrRootPrevDigestNotZero, "h0") {
		t.Fatalf("want ROOT_PREV_DIGEST_NOT_ZERO on h0, got %#v", rep.Errors)
	}
}

// TestHandoffBrokenLinks: in-batch damage in either batch is reported with the
// original codes and ordering, and no splice is returned.
func TestHandoffBrokenLinks(t *testing.T) {
	t.Run("tampered body in first batch", func(t *testing.T) {
		batches := handoffFromPinned(t, nil, identityPerm(0, 1), identityPerm(2, 3))
		for i := range batches.FirstBatch {
			if batches.FirstBatch[i].ID == "h0" {
				batches.FirstBatch[i].Payload = "tampered body"
			}
		}
		rep := audit.AuditHandoff(batches)
		if rep.Valid || rep.Events != nil || rep.TailDigest != "" {
			t.Fatalf("damaged first batch must yield errors only, got %#v", rep)
		}
		codes := codesOf(rep.Errors)
		if got := codes[audit.ErrDigestMismatch]; len(got) != 1 || got[0] != "h0" {
			t.Fatalf("want one DIGEST_MISMATCH on h0, got %#v", rep.Errors)
		}
		// The handoff anchor comparison is undefined when batch 1 has no
		// rebuilt tail: it must not invent a HANDOFF_ANCHOR_MISMATCH even
		// though batch 2 cannot be placed.
		if codes[audit.ErrHandoffAnchorMismatch] != nil {
			t.Fatalf("anchor comparison must be skipped when batch 1 is invalid, got %#v", rep.Errors)
		}
	})

	t.Run("rewired link inside second batch", func(t *testing.T) {
		batches := handoffFromPinned(t, nil, identityPerm(0, 1), identityPerm(2, 3))
		var fake [32]byte
		for i := range fake {
			fake[i] = 0x22
		}
		for i := range batches.SecondBatch {
			if batches.SecondBatch[i].ID == "h3" {
				// Keep h3 internally consistent over the forged anchor so the
				// only defect is the broken link to h2.
				batches.SecondBatch[i].PrevDigest = hex.EncodeToString(fake[:])
				batches.SecondBatch[i].Digest = audit.ComputeDigest("h3", "handoff-3", fake)
			}
		}
		rep := audit.AuditHandoff(batches)
		if rep.Valid || rep.Events != nil {
			t.Fatalf("broken second-batch link must reject, got %#v", rep)
		}
		codes := codesOf(rep.Errors)
		if got := codes[audit.ErrPrevDigestMismatch]; len(got) != 1 || got[0] != "h3" {
			t.Fatalf("want one PREV_DIGEST_MISMATCH on h3, got %#v", rep.Errors)
		}
		if len(codes) != 1 {
			t.Fatalf("pure in-batch link tamper must yield one code, got %#v", rep.Errors)
		}
	})

	t.Run("second batch keeps single-root rule", func(t *testing.T) {
		batches := handoffFromPinned(t, nil, identityPerm(0, 1), identityPerm(2, 3))
		extra := audit.HandoffEvent{
			Event: audit.Event{
				ID:         "x-root",
				ParentID:   "",
				Payload:    "x",
				PrevDigest: audit.ZeroDigest,
				Digest:     audit.ComputeDigest("x-root", "x", [32]byte{}),
			},
			Disclosed: true,
		}
		batches.SecondBatch = append(batches.SecondBatch, extra)
		rep := audit.AuditHandoff(batches)
		if rep.Valid {
			t.Fatal("two roots inside batch 2 must reject")
		}
		codes := codesOf(rep.Errors)
		roots := codes[audit.ErrMultipleRoots]
		if len(roots) != 2 {
			t.Fatalf("want MULTIPLE_ROOTS on h2 and x-root, got %v (%#v)", roots, rep.Errors)
		}
	})
}

// TestHandoffCrossBatchDuplicateID: an id appearing in both batches is rejected
// with the dedicated code even when every batch is internally intact and the
// anchor matches. Constructing the duplicate from ComputeDigest keeps it
// cryptographically consistent with the real first-batch tail.
func TestHandoffCrossBatchDuplicateID(t *testing.T) {
	firstTail := pinnedHandoffChain[1].digest
	tailRaw := mustHashRaw(mustHex(firstTail))

	batches := handoffFromPinned(t, nil, identityPerm(0, 1), nil)
	batches.SecondBatch = []audit.HandoffEvent{{
		Event: audit.Event{
			ID:         "h1", // already used in batch 1
			ParentID:   "",
			Payload:    "handoff-2",
			PrevDigest: firstTail,
			Digest:     audit.ComputeDigest("h1", "handoff-2", tailRaw),
		},
		Disclosed: true,
	}}
	rep := audit.AuditHandoff(batches)
	if rep.Valid || rep.Events != nil {
		t.Fatalf("cross-batch duplicate id must reject, got %#v", rep)
	}
	codes := codesOf(rep.Errors)
	if got := codes[audit.ErrDuplicateIDAcrossBatches]; len(got) != 1 || got[0] != "h1" {
		t.Fatalf("want one DUPLICATE_ID_ACROSS_BATCHES on h1, got %#v", rep.Errors)
	}
	if len(codes) != 1 {
		t.Fatalf("consistent duplicate must yield only the duplicate code, got %#v", rep.Errors)
	}
}

// TestHandoffDuplicateReportedEvenWhenFirstBatchInvalid: the cross-batch rule
// is part of the same audit and survives an invalid first batch, while the
// undefined anchor comparison is still skipped (batch 2 deliberately declares
// a bogus root prevDigest that must not be flagged).
func TestHandoffDuplicateReportedEvenWhenFirstBatchInvalid(t *testing.T) {
	batches := handoffFromPinned(t, nil, identityPerm(0, 1), nil)
	for i := range batches.FirstBatch {
		if batches.FirstBatch[i].ID == "h0" {
			batches.FirstBatch[i].Payload = "tampered body"
		}
	}
	bogus := strings.Repeat("f", 64)
	bogusRaw := mustHashRaw(mustHex(bogus))
	batches.SecondBatch = []audit.HandoffEvent{{
		Event: audit.Event{
			ID:         "h1", // duplicate
			ParentID:   "",
			Payload:    "handoff-2",
			PrevDigest: bogus,
			Digest:     audit.ComputeDigest("h1", "handoff-2", bogusRaw),
		},
		Disclosed: true,
	}}
	rep := audit.AuditHandoff(batches)
	if !hasError(rep.Errors, audit.ErrDigestMismatch, "h0") {
		t.Fatalf("want DIGEST_MISMATCH on h0, got %#v", rep.Errors)
	}
	if !hasError(rep.Errors, audit.ErrDuplicateIDAcrossBatches, "h1") {
		t.Fatalf("duplicate must be reported despite invalid batch 1, got %#v", rep.Errors)
	}
	if codesOf(rep.Errors)[audit.ErrHandoffAnchorMismatch] != nil {
		t.Fatalf("anchor check must be skipped with invalid batch 1, got %#v", rep.Errors)
	}
}

// TestHandoffHiddenTrustPropagation is the headline limited-disclosure
// property across the seam: a withheld body anywhere in batch 1 means even a
// fully disclosed batch 2 only inherits ANCHOR_UNVERIFIED, and the handoff can
// never be VERIFIED.
func TestHandoffHiddenTrustPropagation(t *testing.T) {
	t.Run("hidden first-batch tail poisons the whole second batch", func(t *testing.T) {
		batches := handoffFromPinned(t, map[string]bool{"h1": true},
			identityPerm(1, 0), identityPerm(3, 2)) // both batches shuffled
		rep := audit.AuditHandoff(batches)
		if !rep.Valid || rep.Status != audit.ChainPartial {
			t.Fatalf("want valid/PARTIAL, got %#v errors=%#v", rep, rep.Errors)
		}
		wantStatus := []audit.EventStatus{
			audit.StatusVerifiedPrefix,   // h0 recomputed
			audit.StatusAnchorUnverified, // h1 hidden: the handoff anchor is unverifiable
			audit.StatusAnchorUnverified, // h2 disclosed but anchored on h1
			audit.StatusAnchorUnverified, // h3 disclosed but still behind the gap
		}
		got := make([]audit.EventStatus, 4)
		for i, e := range rep.Events {
			got[i] = e.Status
			if e.ID != pinnedHandoffChain[i].id {
				t.Fatalf("position %d = %s, want %s", i, e.ID, pinnedHandoffChain[i].id)
			}
		}
		if !equalStatuses(got, wantStatus) {
			t.Fatalf("statuses = %v, want %v", got, wantStatus)
		}
		if rep.TailDigest != pinnedHandoffChain[3].digest {
			t.Fatalf("tail digest still reported from declared digests: %s", rep.TailDigest)
		}
	})

	t.Run("hidden second-batch root anchors nothing new", func(t *testing.T) {
		// Batch 1 fully verified; hiding h2 restarts the same trust boundary
		// inside batch 2.
		batches := handoffFromPinned(t, map[string]bool{"h2": true},
			identityPerm(0, 1), identityPerm(2, 3))
		rep := audit.AuditHandoff(batches)
		if !rep.Valid || rep.Status != audit.ChainPartial {
			t.Fatalf("want valid/PARTIAL, got %#v", rep)
		}
		wantStatus := []audit.EventStatus{
			audit.StatusVerifiedPrefix,
			audit.StatusVerifiedPrefix,
			audit.StatusAnchorUnverified,
			audit.StatusAnchorUnverified,
		}
		got := make([]audit.EventStatus, 4)
		for i, e := range rep.Events {
			got[i] = e.Status
		}
		if !equalStatuses(got, wantStatus) {
			t.Fatalf("statuses = %v, want %v", got, wantStatus)
		}
	})

	t.Run("hidden first-batch root verifies nothing", func(t *testing.T) {
		batches := handoffFromPinned(t, map[string]bool{"h0": true},
			identityPerm(0, 1), identityPerm(2, 3))
		rep := audit.AuditHandoff(batches)
		if rep.Status != audit.ChainPartial {
			t.Fatalf("want PARTIAL, got %s", rep.Status)
		}
		for _, e := range rep.Events {
			if e.Status != audit.StatusAnchorUnverified {
				t.Fatalf("%s must be ANCHOR_UNVERIFIED when the first-batch root is hidden, got %s",
					e.ID, e.Status)
			}
		}
	})

	t.Run("disclosed tamper after the seam still hard-errors", func(t *testing.T) {
		batches := handoffFromPinned(t, map[string]bool{"h1": true},
			identityPerm(0, 1), identityPerm(2, 3))
		for i := range batches.SecondBatch {
			if batches.SecondBatch[i].ID == "h3" {
				batches.SecondBatch[i].Payload = "tampered body"
			}
		}
		rep := audit.AuditHandoff(batches)
		if rep.Valid || rep.Events != nil {
			t.Fatalf("disclosed body tamper must hard-error even behind a hidden anchor, got %#v", rep)
		}
		if !hasError(rep.Errors, audit.ErrDigestMismatch, "h3") {
			t.Fatalf("want DIGEST_MISMATCH on h3, got %#v", rep.Errors)
		}
	})
}

// TestHandoffHiddenNeverLeaksAndRendersNull serializes a PARTIAL report with a
// hidden event in each batch and asserts the withheld sentinel cannot appear
// anywhere while payload renders as explicit null.
func TestHandoffHiddenNeverLeaksAndRendersNull(t *testing.T) {
	batches := handoffFromPinned(t, map[string]bool{"h1": true, "h3": true},
		identityPerm(0, 1), identityPerm(2, 3))
	rep := audit.AuditHandoff(batches)
	raw, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if strings.Contains(text, "WITHHELD-BODY") {
		t.Fatalf("withheld body leaked into JSON: %s", text)
	}
	if !strings.Contains(text, `"payload":null`) {
		t.Fatalf("hidden events must render payload:null, got %s", text)
	}
	if strings.Contains(text, `"VERIFIED"`) {
		t.Fatalf("no event may be plain VERIFIED with hidden bodies: %s", text)
	}
}

// TestHandoffErrorsSortedTogether: defects from both batches and the handoff
// level are returned as one list sorted by (code, eventId), same ordering rule
// as the two single-batch entry points.
func TestHandoffErrorsSortedTogether(t *testing.T) {
	batches := handoffFromPinned(t, nil, identityPerm(0, 1), nil)
	// Batch 1: body tamper on h0.
	for i := range batches.FirstBatch {
		if batches.FirstBatch[i].ID == "h0" {
			batches.FirstBatch[i].Payload = "changed"
		}
	}
	// Batch 2: a single root whose id is duplicated and whose prevDigest is
	// bogus. Batch 1 has no rebuilt tail so the anchor comparison is skipped;
	// the remaining defects span both levels nonetheless.
	bogus := strings.Repeat("e", 64)
	bogusRaw := mustHashRaw(mustHex(bogus))
	batches.SecondBatch = []audit.HandoffEvent{{
		Event: audit.Event{
			ID:         "h1",
			ParentID:   "",
			Payload:    "handoff-2",
			PrevDigest: bogus,
			Digest:     audit.ComputeDigest("h1", "handoff-2", bogusRaw),
		},
		Disclosed: true,
	}}
	rep := audit.AuditHandoff(batches)
	if rep.Valid {
		t.Fatal("want invalid report")
	}
	if len(rep.Errors) < 2 {
		t.Fatalf("want defects from both levels, got %#v", rep.Errors)
	}
	for i := 1; i < len(rep.Errors); i++ {
		a, b := rep.Errors[i-1], rep.Errors[i]
		if a.Code > b.Code || (a.Code == b.Code && a.EventID > b.EventID) {
			t.Fatalf("errors not sorted by (code,eventId): %#v before %#v; full %#v",
				a, b, rep.Errors)
		}
	}
	if !hasError(rep.Errors, audit.ErrDigestMismatch, "h0") ||
		!hasError(rep.Errors, audit.ErrDuplicateIDAcrossBatches, "h1") {
		t.Fatalf("want DIGEST_MISMATCH/h0 and DUPLICATE_ID_ACROSS_BATCHES/h1, got %#v", rep.Errors)
	}
}
