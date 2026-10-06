package audit_test

import (
	"encoding/json"
	"math/rand"
	"strings"
	"testing"

	"sealaudit/internal/audit"
)

// Pinned vectors computed independently of production code (Python, SHA-256
// over the spec buffer) for ids v0..v3, payloads body-0..body-3:
//
//	v0 root -> 1dd5192560a245aa6df46e3fe561de9842eaec04fa922b770d160bc8aaf0a0b7
//	v1      -> 99b9cff23861e36f06708e966351f1723d803323d0e3a0d016655a95035c58b8
//	v2      -> c59ed192115a7466e2371a6aa23b7b5ddc637d92ea01eae685f6ece69cc46bd9
//	v3 tail -> caebe7a58c8339810ebe10bab9f1b8765a241ae1315a9e1dea4a27c04ea2be9e
//
// The tests below construct events from these pinned digests rather than from
// ComputeDigest, so a changed digest definition would break them outright.
var pinnedLimitedChain = []struct {
	id, payload, prevDigest, digest string
}{
	{"v0", "body-0", audit.ZeroDigest, "1dd5192560a245aa6df46e3fe561de9842eaec04fa922b770d160bc8aaf0a0b7"},
	{"v1", "body-1", "1dd5192560a245aa6df46e3fe561de9842eaec04fa922b770d160bc8aaf0a0b7", "99b9cff23861e36f06708e966351f1723d803323d0e3a0d016655a95035c58b8"},
	{"v2", "body-2", "99b9cff23861e36f06708e966351f1723d803323d0e3a0d016655a95035c58b8", "c59ed192115a7466e2371a6aa23b7b5ddc637d92ea01eae685f6ece69cc46bd9"},
	{"v3", "body-3", "c59ed192115a7466e2371a6aa23b7b5ddc637d92ea01eae685f6ece69cc46bd9", "caebe7a58c8339810ebe10bab9f1b8765a241ae1315a9e1dea4a27c04ea2be9e"},
}

// limitedFromPinned builds a LimitedEvent slice from the pinned vectors.
// hidden is the set of ids whose payload is withheld; their Payload field is
// deliberately left as a sentinel string that must never be inspected.
func limitedFromPinned(t *testing.T, hidden map[string]bool, perm ...int) []audit.LimitedEvent {
	t.Helper()
	order := perm
	if order == nil {
		order = make([]int, len(pinnedLimitedChain))
		for i := range order {
			order[i] = i
		}
	}
	out := make([]audit.LimitedEvent, len(order))
	for pos, i := range order {
		v := pinnedLimitedChain[i]
		le := audit.LimitedEvent{
			Event: audit.Event{
				ID:         v.id,
				ParentID:   "",
				PrevDigest: v.prevDigest,
				Digest:     v.digest,
			},
			Disclosed: !hidden[v.id],
		}
		if i > 0 {
			le.ParentID = pinnedLimitedChain[i-1].id
		}
		if le.Disclosed {
			le.Payload = v.payload
		} else {
			// The real body never reaches the auditor; even this sentinel
			// must not appear in any output.
			le.Payload = "WITHHELD-BODY-MUST-NOT-LEAK-" + v.id
		}
		out[pos] = le
	}
	return out
}

func statusesOf(rep audit.LimitedReport) []audit.EventStatus {
	out := make([]audit.EventStatus, len(rep.Events))
	for i, e := range rep.Events {
		out[i] = e.Status
	}
	return out
}

func payloadOf(rep audit.LimitedReport, id string) (*string, bool) {
	for _, e := range rep.Events {
		if e.ID == id {
			return e.Payload, e.Payload != nil
		}
	}
	return nil, false
}

// TestLimitedAllDisclosedIsVerified: with no withheld bodies the limited
// entry point behaves like the strict audit: everything recomputes from the
// pinned vectors.
func TestLimitedAllDisclosedIsVerified(t *testing.T) {
	rep := audit.AuditLimited(limitedFromPinned(t, nil))
	if !rep.Valid || rep.Status != audit.ChainVerified {
		t.Fatalf("want valid/VERIFIED, got %#v errors=%#v", rep, rep.Errors)
	}
	if len(rep.Events) != 4 {
		t.Fatalf("want 4 rebuilt events, got %d", len(rep.Events))
	}
	for i, e := range rep.Events {
		if e.ID != pinnedLimitedChain[i].id {
			t.Fatalf("position %d = %s, want %s (graph rebuild, not upload order)",
				i, e.ID, pinnedLimitedChain[i].id)
		}
		if e.Status != audit.StatusVerified {
			t.Fatalf("%s status %s, want VERIFIED", e.ID, e.Status)
		}
		if e.Payload == nil || *e.Payload != pinnedLimitedChain[i].payload {
			t.Fatalf("%s payload not echoed as disclosed: %v", e.ID, e.Payload)
		}
	}
	if rep.TailDigest != pinnedLimitedChain[3].digest {
		t.Fatalf("tailDigest = %s", rep.TailDigest)
	}
}

// TestLimitedRootHidden: the very first event withheld means nothing is a
// verified prefix; the chain is PARTIAL and every event is anchor-only.
func TestLimitedRootHidden(t *testing.T) {
	rep := audit.AuditLimited(limitedFromPinned(t, map[string]bool{"v0": true}))
	if !rep.Valid {
		t.Fatalf("structure intact, want valid report, got errors %#v", rep.Errors)
	}
	if rep.Status != audit.ChainPartial {
		t.Fatalf("want PARTIAL, got %s", rep.Status)
	}
	want := []audit.EventStatus{
		audit.StatusAnchorUnverified,
		audit.StatusAnchorUnverified,
		audit.StatusAnchorUnverified,
		audit.StatusAnchorUnverified,
	}
	if got := statusesOf(rep); !equalStatuses(got, want) {
		t.Fatalf("root hidden: statuses = %v, want %v", got, want)
	}
	if p, present := payloadOf(rep, "v0"); present || p != nil {
		t.Fatalf("hidden root payload must be null/absent, got %v", p)
	}
}

// TestLimitedMiddleHidden: the run before the hidden event is a verified
// prefix; the hidden event and all successors are anchor-unverified.
func TestLimitedMiddleHidden(t *testing.T) {
	rep := audit.AuditLimited(limitedFromPinned(t, map[string]bool{"v2": true}))
	if !rep.Valid || rep.Status != audit.ChainPartial {
		t.Fatalf("want valid/PARTIAL, got valid=%v status=%s errs=%#v",
			rep.Valid, rep.Status, rep.Errors)
	}
	want := []audit.EventStatus{
		audit.StatusVerifiedPrefix,
		audit.StatusVerifiedPrefix,
		audit.StatusAnchorUnverified,
		audit.StatusAnchorUnverified,
	}
	if got := statusesOf(rep); !equalStatuses(got, want) {
		t.Fatalf("middle hidden: statuses = %v, want %v", got, want)
	}
	if p, present := payloadOf(rep, "v2"); present || p != nil {
		t.Fatalf("hidden payload must be null/absent, got %v", p)
	}
	// Disclosed bodies around the gap are still echoed.
	if p, present := payloadOf(rep, "v3"); !present || p == nil || *p != "body-3" {
		t.Fatalf("disclosed successor body must be echoed, got %v present=%v", p, present)
	}
	if rep.TailDigest != pinnedLimitedChain[3].digest {
		t.Fatalf("tail digest still reported from declared digests: got %s", rep.TailDigest)
	}
}

// TestLimitedTailHidden: the prefix covers all but the tail.
func TestLimitedTailHidden(t *testing.T) {
	rep := audit.AuditLimited(limitedFromPinned(t, map[string]bool{"v3": true}))
	if !rep.Valid || rep.Status != audit.ChainPartial {
		t.Fatalf("want valid/PARTIAL, got %#v", rep)
	}
	want := []audit.EventStatus{
		audit.StatusVerifiedPrefix,
		audit.StatusVerifiedPrefix,
		audit.StatusVerifiedPrefix,
		audit.StatusAnchorUnverified,
	}
	if got := statusesOf(rep); !equalStatuses(got, want) {
		t.Fatalf("tail hidden: statuses = %v, want %v", got, want)
	}
}

// TestLimitedHiddenNeverVerified is the headline security property: across
// every possible hidden position (and combinations), no hidden event may ever
// carry VERIFIED or VERIFIED_PREFIX, and the chain may never be VERIFIED.
func TestLimitedHiddenNeverVerified(t *testing.T) {
	subsets := [][]string{
		{"v0"}, {"v1"}, {"v2"}, {"v3"},
		{"v0", "v3"}, {"v1", "v2"}, {"v0", "v1", "v2", "v3"},
	}
	for _, set := range subsets {
		hidden := map[string]bool{}
		for _, id := range set {
			hidden[id] = true
		}
		rep := audit.AuditLimited(limitedFromPinned(t, hidden))
		if rep.Status == audit.ChainVerified {
			t.Fatalf("hidden %v: chain must not be VERIFIED", set)
		}
		for _, e := range rep.Events {
			if hidden[e.ID] {
				if e.Status != audit.StatusAnchorUnverified {
					t.Fatalf("hidden %v status = %s, must be ANCHOR_UNVERIFIED", e.ID, e.Status)
				}
				if e.Payload != nil {
					t.Fatalf("hidden %v payload echoed: %q", e.ID, *e.Payload)
				}
			}
		}
	}
}

// TestLimitedDisclosedTamperDetected: tampering a disclosed body is still a
// hard DIGEST_MISMATCH error; no partial chain is returned.
func TestLimitedDisclosedTamperDetected(t *testing.T) {
	events := limitedFromPinned(t, map[string]bool{"v3": true})
	for i := range events {
		if events[i].ID == "v1" {
			events[i].Payload = "tampered body"
		}
	}
	rep := audit.AuditLimited(events)
	if rep.Valid || rep.Events != nil || rep.TailDigest != "" {
		t.Fatalf("tampered disclosed body must yield errors only, got %#v", rep)
	}
	codes := codesOf(rep.Errors)
	if got := codes[audit.ErrDigestMismatch]; len(got) != 1 || got[0] != "v1" {
		t.Fatalf("want one DIGEST_MISMATCH on v1, got %#v", rep.Errors)
	}
	if len(codes) != 1 {
		t.Fatalf("body tamper must not be structural damage, got %#v", rep.Errors)
	}
}

// TestLimitedForgedLinkDetected: rewiring a link (prevDigest no longer equals
// the parent's declared digest) is rejected even with a hidden parent; the
// hidden body cannot launder a forged link.
func TestLimitedForgedLinkDetected(t *testing.T) {
	events := limitedFromPinned(t, map[string]bool{"v2": true})
	// v3 claims a bogus anchor; its own digest stays the pinned one (so it
	// would recompute if v3's body were disclosed, proving the link check is
	// independent).
	for i := range events {
		if events[i].ID == "v3" {
			events[i].PrevDigest = strings.Repeat("f", 64)
		}
	}
	rep := audit.AuditLimited(events)
	if rep.Valid || rep.Events != nil {
		t.Fatalf("forged link must reject, got %#v", rep)
	}
	if !hasError(rep.Errors, audit.ErrPrevDigestMismatch, "v3") {
		t.Fatalf("want PREV_DIGEST_MISMATCH on v3, got %#v", rep.Errors)
	}
}

// TestLimitedStructuralDamageStillErrors: forks and cycles are caught under
// limited disclosure exactly as under strict audit, including when hidden
// events participate.
func TestLimitedStructuralDamageStillErrors(t *testing.T) {
	t.Run("fork with hidden parent-side events", func(t *testing.T) {
		events := limitedFromPinned(t, map[string]bool{"v1": true})
		// Repoint v3 at v1: v1 then has children v2 and v3.
		for i := range events {
			if events[i].ID == "v3" {
				events[i].ParentID = "v1"
			}
		}
		rep := audit.AuditLimited(events)
		if rep.Valid || rep.Events != nil {
			t.Fatalf("fork must reject even with hidden events, got %#v", rep)
		}
		if !hasError(rep.Errors, audit.ErrFork, "v1") {
			t.Fatalf("want FORK on v1, got %#v", rep.Errors)
		}
	})

	t.Run("cycle including hidden event", func(t *testing.T) {
		events := limitedFromPinned(t, map[string]bool{"v2": true})
		for i := range events {
			if events[i].ID == "v0" {
				events[i].ParentID = "v3" // close the ring
			}
		}
		rep := audit.AuditLimited(events)
		if rep.Valid || rep.Events != nil {
			t.Fatalf("cycle must reject, got %#v", rep)
		}
		if !hasError(rep.Errors, audit.ErrCycle, "v2") {
			t.Fatalf("hidden cycle member v2 must still be CYCLE, got %#v", rep.Errors)
		}
		if !hasError(rep.Errors, audit.ErrNoRoot, "") {
			t.Fatalf("ring must report NO_ROOT, got %#v", rep.Errors)
		}
	})
}

// TestLimitedOrderIndependent: shuffled uploads with a hidden middle event
// still rebuild the identical root-to-tail order with identical statuses.
func TestLimitedOrderIndependent(t *testing.T) {
	r := rand.New(rand.NewSource(20260925))
	hidden := map[string]bool{"v2": true}
	base := limitedFromPinned(t, hidden)

	wantIDs := []string{"v0", "v1", "v2", "v3"}
	wantStatus := []audit.EventStatus{
		audit.StatusVerifiedPrefix,
		audit.StatusVerifiedPrefix,
		audit.StatusAnchorUnverified,
		audit.StatusAnchorUnverified,
	}
	for iter := 0; iter < 50; iter++ {
		rep := audit.AuditLimited(shuffledLimitedCopy(t, base, r))
		if !rep.Valid || rep.Status != audit.ChainPartial {
			t.Fatalf("iter %d: want valid/PARTIAL, got %#v %#v", iter, rep, rep.Errors)
		}
		if len(rep.Events) != 4 {
			t.Fatalf("iter %d: got %d events", iter, len(rep.Events))
		}
		for i, e := range rep.Events {
			if e.ID != wantIDs[i] {
				t.Fatalf("iter %d: position %d = %s, want %s", iter, i, e.ID, wantIDs[i])
			}
			if e.Status != wantStatus[i] {
				t.Fatalf("iter %d: %s status = %s, want %s",
					iter, e.ID, e.Status, wantStatus[i])
			}
		}
	}
}

// TestLimitedErrorsSortedSameWay: the limited entry point must reuse the exact
// (code, eventId) ordering as the strict audit.
func TestLimitedErrorsSortedSameWay(t *testing.T) {
	events := limitedFromPinned(t, map[string]bool{"v3": true})
	for i := range events {
		switch events[i].ID {
		case "v1":
			events[i].Payload = "changed" // DIGEST_MISMATCH
		case "v2":
			events[i].ParentID = "ghost" // MISSING_PARENT
		}
	}
	rep := audit.AuditLimited(events)
	if rep.Valid {
		t.Fatal("want invalid report")
	}
	for i := 1; i < len(rep.Errors); i++ {
		a, b := rep.Errors[i-1], rep.Errors[i]
		if a.Code > b.Code || (a.Code == b.Code && a.EventID > b.EventID) {
			t.Fatalf("errors not sorted by (code,eventId): %#v before %#v; full %#v",
				a, b, rep.Errors)
		}
	}
}

// TestLimitedJSONNeverEchoesHiddenBody serializes a result and asserts the
// withheld sentinel string cannot appear anywhere in the bytes, and payload
// is rendered as explicit null.
func TestLimitedJSONNeverEchoesHiddenBody(t *testing.T) {
	events := limitedFromPinned(t, map[string]bool{"v1": true})
	rep := audit.AuditLimited(events)
	raw, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if strings.Contains(text, "WITHHELD-BODY") {
		t.Fatalf("withheld body leaked into JSON: %s", text)
	}
	if !strings.Contains(text, `"payload":null`) {
		t.Fatalf("hidden event must render payload:null, got %s", text)
	}
}

func shuffledLimitedCopy(t *testing.T, in []audit.LimitedEvent, r *rand.Rand) []audit.LimitedEvent {
	t.Helper()
	out := append([]audit.LimitedEvent(nil), in...)
	r.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

func equalStatuses(a, b []audit.EventStatus) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
