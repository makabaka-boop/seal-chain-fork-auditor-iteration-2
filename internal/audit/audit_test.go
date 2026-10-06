package audit_test

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/rand"
	"testing"

	"sealaudit/internal/audit"
)

// buildChain builds a cryptographically consistent chain of n events in
// root-to-tail order.
func buildChain(n int) []audit.Event {
	events := make([]audit.Event, n)
	var prevRaw [32]byte
	prevDigest := audit.ZeroDigest
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("evt-%03d", i)
		payload := fmt.Sprintf("payload-%d", i)
		digest := audit.ComputeDigest(id, payload, prevRaw)
		parentID := ""
		if i > 0 {
			parentID = events[i-1].ID
		}
		events[i] = audit.Event{
			ID:         id,
			ParentID:   parentID,
			Payload:    payload,
			PrevDigest: prevDigest,
			Digest:     digest,
		}
		prevDigest = digest
		copy(prevRaw[:], mustHex(digest))
	}
	return events
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func shuffledCopy(t *testing.T, in []audit.Event, r *rand.Rand) []audit.Event {
	t.Helper()
	out := append([]audit.Event(nil), in...)
	r.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

func hasError(errs []audit.ChainError, code audit.ErrorCode, eventID string) bool {
	for _, e := range errs {
		if e.Code == code && e.EventID == eventID {
			return true
		}
	}
	return false
}

func codesOf(errs []audit.ChainError) map[audit.ErrorCode][]string {
	out := make(map[audit.ErrorCode][]string)
	for _, e := range errs {
		out[e.Code] = append(out[e.Code], e.EventID)
	}
	return out
}

// TestValidChainOrderIndependent is the headline property: batches uploaded
// from many workstations in arbitrary order must still be rebuilt root-to-tail.
func TestValidChainOrderIndependent(t *testing.T) {
	r := rand.New(rand.NewSource(20260924))
	events := buildChain(30)
	tail := events[len(events)-1].Digest

	for iter := 0; iter < 50; iter++ {
		rep := audit.Audit(shuffledCopy(t, events, r))
		if !rep.Valid {
			t.Fatalf("iteration %d: expected valid chain, got errors %#v", iter, rep.Errors)
		}
		if len(rep.Events) != len(events) {
			t.Fatalf("iteration %d: got %d events, want %d", iter, len(rep.Events), len(events))
		}
		for i, e := range rep.Events {
			if e.ID != events[i].ID {
				t.Fatalf("iteration %d: position %d is %s, want %s (order must not depend on upload order)",
					iter, i, e.ID, events[i].ID)
			}
		}
		if rep.TailDigest != tail {
			t.Fatalf("iteration %d: tail digest %s, want %s", iter, rep.TailDigest, tail)
		}
	}
}

// TestBodyTamperDetected: changing a payload breaks only that event's digest;
// links still line up, so the auditor can tell body tampering from link damage.
func TestBodyTamperDetected(t *testing.T) {
	r := rand.New(rand.NewSource(7))
	events := shuffledCopy(t, buildChain(8), r)
	const victim = "evt-003"
	for i := range events {
		if events[i].ID == victim {
			events[i].Payload = "tampered body"
		}
	}

	rep := audit.Audit(events)
	if rep.Valid {
		t.Fatal("tampered payload must invalidate the chain")
	}
	codes := codesOf(rep.Errors)
	if got := codes[audit.ErrDigestMismatch]; len(got) != 1 || got[0] != victim {
		t.Fatalf("want exactly one DIGEST_MISMATCH on %s, got %#v", victim, rep.Errors)
	}
	if len(codes) != 1 {
		t.Fatalf("body tampering must not be reported as structural damage, got %#v", rep.Errors)
	}
}

// TestParentReferenceTamperToMissingID: repointing an event at an unknown id is
// a missing predecessor, and is distinguishable from both body tampering and a
// fork.
func TestParentReferenceTamperToMissingID(t *testing.T) {
	r := rand.New(rand.NewSource(11))
	events := shuffledCopy(t, buildChain(6), r)
	const victim = "evt-002"
	for i := range events {
		if events[i].ID == victim {
			events[i].ParentID = "offline-workstation-ghost"
		}
	}

	rep := audit.Audit(events)
	if rep.Valid {
		t.Fatal("dangling parent reference must invalidate the chain")
	}
	codes := codesOf(rep.Errors)
	if got := codes[audit.ErrMissingParent]; len(got) != 1 || got[0] != victim {
		t.Fatalf("want one MISSING_PARENT on %s, got %#v", victim, rep.Errors)
	}
	if len(codes) != 1 {
		t.Fatalf("dangling parent must yield only MISSING_PARENT, got %#v", rep.Errors)
	}
}

// TestPrevLinkTamperDetected: an event self-consistent with a rewritten anchor
// (its own digest recomputed over the fake prevDigest) breaks only the link to
// its parent, isolating PREV_DIGEST_MISMATCH from body tampering. Using the
// tail keeps the damage confined to one event.
func TestPrevLinkTamperDetected(t *testing.T) {
	events := buildChain(4)
	const victim = "evt-003"
	var fakeAnchor [32]byte
	for i := range fakeAnchor {
		fakeAnchor[i] = 0x11
	}
	events[3].PrevDigest = hex.EncodeToString(fakeAnchor[:])
	events[3].Digest = audit.ComputeDigest(events[3].ID, events[3].Payload, fakeAnchor)

	rep := audit.Audit(events)
	if rep.Valid {
		t.Fatal("broken prevDigest link must invalidate the chain")
	}
	codes := codesOf(rep.Errors)
	if got := codes[audit.ErrPrevDigestMismatch]; len(got) != 1 || got[0] != victim {
		t.Fatalf("want one PREV_DIGEST_MISMATCH on %s, got %#v", victim, rep.Errors)
	}
	if len(codes) != 1 {
		t.Fatalf("pure link tampering must yield only PREV_DIGEST_MISMATCH, got %#v", rep.Errors)
	}
}

// TestPrevAnchorRewriteAlsoBreaksOwnDigest: when the prevDigest bytes change
// but the declared digest is not refreshed, both the link check and the own
// digest recomputation must fail — the auditor reports both defects.
func TestPrevAnchorRewriteAlsoBreaksOwnDigest(t *testing.T) {
	events := buildChain(4)
	events[3].PrevDigest = "1111111111111111111111111111111111111111111111111111111111111111"
	rep := audit.Audit(events)
	if !hasError(rep.Errors, audit.ErrPrevDigestMismatch, "evt-003") ||
		!hasError(rep.Errors, audit.ErrDigestMismatch, "evt-003") {
		t.Fatalf("expected both PREV_DIGEST_MISMATCH and DIGEST_MISMATCH, got %#v", rep.Errors)
	}
}

// TestForkDetected: two children claiming the same predecessor. The error is
// anchored on the parent id and the chain must be rejected.
func TestForkDetected(t *testing.T) {
	chain := buildChain(3) // evt-000 <- evt-001 <- evt-002

	forkRaw := mustHashRaw(mustHex(chain[0].Digest))
	fork := audit.Event{
		ID:         "evt-fork",
		ParentID:   "evt-000", // sibling of evt-001
		Payload:    "fork payload",
		PrevDigest: chain[0].Digest,
		Digest:     audit.ComputeDigest("evt-fork", "fork payload", forkRaw),
	}
	events := []audit.Event{chain[2], fork, chain[0], chain[1]} // deliberately unordered

	rep := audit.Audit(events)
	if rep.Valid {
		t.Fatal("forked predecessor must invalidate the chain")
	}
	codes := codesOf(rep.Errors)
	if got := codes[audit.ErrFork]; len(got) != 1 || got[0] != "evt-000" {
		t.Fatalf("want one FORK anchored on evt-000, got %#v", rep.Errors)
	}
	if len(codes) != 1 {
		t.Fatalf("a cleanly-built fork must yield only FORK, got %#v", rep.Errors)
	}
}

// TestParentRewireCreatesForkAndMismatch: re-pointing an existing middle event
// at another existing parent both forks that parent and breaks the prevDigest
// link, proving the auditor separates structural from hash damage.
func TestParentRewireCreatesForkAndMismatch(t *testing.T) {
	events := buildChain(6)
	// evt-004 originally child of evt-003; re-point it at evt-001, colliding
	// with evt-002.
	const victim = "evt-004"
	for i := range events {
		if events[i].ID == victim {
			events[i].ParentID = "evt-001"
		}
	}
	rep := audit.Audit(events)
	if !hasError(rep.Errors, audit.ErrFork, "evt-001") {
		t.Fatalf("expected FORK on evt-001, got %#v", rep.Errors)
	}
	if !hasError(rep.Errors, audit.ErrPrevDigestMismatch, victim) {
		t.Fatalf("expected PREV_DIGEST_MISMATCH on %s, got %#v", victim, rep.Errors)
	}
	if len(rep.Errors) != 2 {
		t.Fatalf("re-wire must yield exactly FORK + PREV_DIGEST_MISMATCH, got %#v", rep.Errors)
	}
}

// TestCycleDetected: repointing the root at the tail closes a ring; every
// member must be reported, once each, regardless of traversal entry point.
func TestCycleDetected(t *testing.T) {
	events := buildChain(5)
	events[0].ParentID = "evt-004" // close the ring

	rep := audit.Audit(events)
	codes := codesOf(rep.Errors)
	got := codes[audit.ErrCycle]
	if len(got) != 5 {
		t.Fatalf("want all 5 cycle members flagged, got %v (full: %#v)", got, rep.Errors)
	}
	// Every member exactly once after dedup.
	seen := map[string]bool{}
	for _, id := range got {
		if seen[id] {
			t.Fatalf("cycle member %s reported twice", id)
		}
		seen[id] = true
	}
	// A closed ring has no root as well; that must be reported too.
	if !hasError(rep.Errors, audit.ErrNoRoot, "") {
		t.Fatalf("ring must also report NO_ROOT, got %#v", rep.Errors)
	}
}

// TestSelfLoopDetected covers the smallest possible cycle.
func TestSelfLoopDetected(t *testing.T) {
	events := buildChain(1)
	events[0].ParentID = "evt-000"
	rep := audit.Audit(events)
	if !hasError(rep.Errors, audit.ErrCycle, "evt-000") {
		t.Fatalf("self-loop must be CYCLE, got %#v", rep.Errors)
	}
}

// TestRootAnomalyMustBeZero: the sole root with a non-zero prevDigest gets the
// dedicated code, independent of its own digest validity.
func TestRootAnomalyMustBeZero(t *testing.T) {
	e := audit.Event{
		ID:         "root",
		ParentID:   "",
		Payload:    "p",
		PrevDigest: "0101010101010101010101010101010101010101010101010101010101010101",
	}
	var anchor [32]byte
	for i := range anchor {
		anchor[i] = 0x01
	}
	e.Digest = audit.ComputeDigest("root", "p", anchor) // internally consistent, wrong anchor

	rep := audit.Audit([]audit.Event{e})
	if !hasError(rep.Errors, audit.ErrRootPrevDigestNotZero, "root") {
		t.Fatalf("non-zero root anchor must be ROOT_PREV_DIGEST_NOT_ZERO, got %#v", rep.Errors)
	}
	// The event is otherwise internally consistent, so no body-tamper code.
	for _, e := range rep.Errors {
		if e.Code == audit.ErrDigestMismatch {
			t.Fatalf("consistent digest must not be flagged DIGEST_MISMATCH, got %#v", rep.Errors)
		}
	}
}

func TestMultipleRoots(t *testing.T) {
	chain := buildChain(2) // root evt-000, child evt-001
	other := audit.Event{
		ID:         "other-root",
		ParentID:   "",
		Payload:    "p",
		PrevDigest: audit.ZeroDigest,
	}
	var zero [32]byte
	other.Digest = audit.ComputeDigest("other-root", "p", zero)

	rep := audit.Audit([]audit.Event{chain[1], other, chain[0]})
	codes := codesOf(rep.Errors)
	got := codes[audit.ErrMultipleRoots]
	if len(got) != 2 {
		t.Fatalf("want MULTIPLE_ROOTS on both roots, got %v (%#v)", got, rep.Errors)
	}
}

func TestNoRoot(t *testing.T) {
	events := buildChain(3)
	events[0].ParentID = "missing-parent"
	rep := audit.Audit(events)
	codes := codesOf(rep.Errors)
	if !hasError(rep.Errors, audit.ErrNoRoot, "") {
		t.Fatalf("want NO_ROOT with empty eventId, got %#v", rep.Errors)
	}
	if got := codes[audit.ErrMissingParent]; len(got) != 1 || got[0] != "evt-000" {
		t.Fatalf("want MISSING_PARENT on evt-000, got %v", got)
	}
}

// TestErrorsSortedByCodeThenID is the required deterministic reporting order.
func TestErrorsSortedByCodeThenID(t *testing.T) {
	chain := buildChain(5)
	// Multiple roots.
	extra := audit.Event{ID: "zz-root", ParentID: "", Payload: "z", PrevDigest: audit.ZeroDigest, Digest: audit.ComputeDigest("zz-root", "z", [32]byte{})}
	// Fork parent evt-001 by re-parenting evt-004, plus body tamper on
	// evt-002, plus a dangling parent on evt-003: exercises several codes.
	for i := range chain {
		switch chain[i].ID {
		case "evt-004":
			chain[i].ParentID = "evt-001"
		case "evt-002":
			chain[i].Payload = "changed"
		case "evt-003":
			chain[i].ParentID = "ghost"
		}
	}
	rep := audit.Audit([]audit.Event{chain[4], extra, chain[0], chain[2], chain[1], chain[3]})
	if rep.Valid {
		t.Fatal("expected invalid report")
	}
	for i := 1; i < len(rep.Errors); i++ {
		a, b := rep.Errors[i-1], rep.Errors[i]
		if a.Code > b.Code || (a.Code == b.Code && a.EventID > b.EventID) {
			t.Fatalf("errors not sorted by (code,eventId): %#v before %#v; full %#v", a, b, rep.Errors)
		}
	}
	// Ensure the damaged batch surfaces distinct, distinguishable categories.
	codes := codesOf(rep.Errors)
	for _, want := range []audit.ErrorCode{
		audit.ErrMissingParent, audit.ErrFork, audit.ErrPrevDigestMismatch,
		audit.ErrDigestMismatch, audit.ErrMultipleRoots,
	} {
		if len(codes[want]) == 0 {
			t.Fatalf("expected error code %s in %#v", want, rep.Errors)
		}
	}
}

// TestSingleEventRootChain covers the minimal valid batch.
func TestSingleEventRootChain(t *testing.T) {
	e := audit.Event{ID: "only", ParentID: "", Payload: "data", PrevDigest: audit.ZeroDigest}
	e.Digest = audit.ComputeDigest(e.ID, e.Payload, [32]byte{})
	rep := audit.Audit([]audit.Event{e})
	if !rep.Valid || len(rep.Events) != 1 || rep.TailDigest != e.Digest {
		t.Fatalf("single root must be a valid chain, got %#v", rep)
	}
}

// TestInvalidChainReturnsNoEventsAndTail: the root-to-tail sequence and tail
// digest are emitted only when the chain is complete and consistent.
func TestInvalidChainReturnsNoEventsAndTail(t *testing.T) {
	events := buildChain(3)
	events[1].Payload = "x"
	rep := audit.Audit(events)
	if rep.Valid || rep.Events != nil || rep.TailDigest != "" {
		t.Fatalf("invalid report must omit events/tailDigest, got %#v", rep)
	}
}

// TestByteExactLayout independently rebuilds the signed buffer from the spec
// (bypassing ComputeDigest) so the byte order is verified, not just self-
// consistency. Includes multibyte UTF-8 and a hard-coded vector computed
// outside Go.
func TestByteExactLayout(t *testing.T) {
	const id = "根-1"
	const payload = "α"

	var prev [32]byte
	buf := specBuffer(id, payload, prev)

	const pinned = "b17a3ef4f1ce4ada24925ef39e4b326e163280aef3133399b86ecb95aa93b587"
	got := fmt.Sprintf("%x", sha256.Sum256(buf))
	if got != pinned {
		t.Fatalf("independent byte layout hash = %s, want pinned %s", got, pinned)
	}
	if audit.ComputeDigest(id, payload, prev) != pinned {
		t.Fatal("ComputeDigest must reproduce the pinned vector")
	}

	// ASCII chain vectors also pinned independently.
	r1 := specBuffer("r1", "root", [32]byte{})
	rh := sha256.Sum256(r1)
	if hex.EncodeToString(rh[:]) != "3a83011f8c15d3bc1c5080a7be8589e2f19a7191980841a44d8bce84aac4be70" {
		t.Fatal("root vector mismatch")
	}
	c1 := specBuffer("c1", "child", rh)
	ch := sha256.Sum256(c1)
	if hex.EncodeToString(ch[:]) != "7e033049f76f882a851806f8ddb883eb979770877899e0798c8ed4a4f453d6f8" {
		t.Fatal("child vector mismatch")
	}
	t2 := specBuffer("t2", "tail", ch)
	th := sha256.Sum256(t2)
	if hex.EncodeToString(th[:]) != "cc727085073d82c236c704fda046118e86099c53d61370f86036e52896c852b5" {
		t.Fatal("tail vector mismatch")
	}
	if audit.ComputeDigest("t2", "tail", ch) != hex.EncodeToString(th[:]) {
		t.Fatal("ComputeDigest tail mismatch")
	}
}

// specBuffer constructs the exact concatenation defined by the digest spec,
// written independently from the production helper.
func specBuffer(id, payload string, prev [32]byte) []byte {
	idB, payloadB := []byte(id), []byte(payload)
	out := make([]byte, 0, 4+len(idB)+32+4+len(payloadB))
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(idB)))
	out = append(out, l[:]...)
	out = append(out, idB...)
	out = append(out, prev[:]...)
	binary.BigEndian.PutUint32(l[:], uint32(len(payloadB)))
	out = append(out, l[:]...)
	out = append(out, payloadB...)
	return out
}

func mustHashRaw(b []byte) [32]byte {
	if len(b) != 32 {
		panic("expected 32 raw digest bytes")
	}
	var out [32]byte
	copy(out[:], b)
	return out
}
