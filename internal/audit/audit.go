// Package audit validates and rebuilds hash-chained evidence-seal events.
//
// Events may be uploaded by different workstations in arbitrary order, so all
// checks operate purely on the id/parentId graph and the declared digests;
// the upload order is never trusted.
package audit

import (
	"encoding/hex"
	"sort"
)

// Event is one evidence-seal registration record.
type Event struct {
	ID         string `json:"id"`
	ParentID   string `json:"parentId"`
	Payload    string `json:"payload"`
	PrevDigest string `json:"prevDigest"`
	Digest     string `json:"digest"`
}

// ErrorCode identifies exactly one kind of integrity failure. Distinct codes
// let an auditor tell structural damage apart from hash-level tampering.
type ErrorCode string

const (
	// ErrMultipleRoots is reported for every root when the graph has more
	// than one root event (eventId is the offending root id).
	ErrMultipleRoots ErrorCode = "MULTIPLE_ROOTS"
	// ErrNoRoot is reported when the graph has no root event. Because there
	// is no offending event, eventId is the empty string.
	ErrNoRoot ErrorCode = "NO_ROOT"
	// ErrMissingParent is reported for an event whose parentId does not
	// refer to any event in the batch.
	ErrMissingParent ErrorCode = "MISSING_PARENT"
	// ErrFork is reported once per parent with more than one child. The
	// eventId carries the parent id that forks.
	ErrFork ErrorCode = "FORK"
	// ErrCycle is reported for every event that lies on a directed cycle.
	ErrCycle ErrorCode = "CYCLE"
	// ErrRootPrevDigestNotZero is reported when the (single) root event
	// declares a non-zero prevDigest.
	ErrRootPrevDigestNotZero ErrorCode = "ROOT_PREV_DIGEST_NOT_ZERO"
	// ErrPrevDigestMismatch is reported when a non-root event's prevDigest
	// differs from its parent event's declared digest: a broken or
	// re-wired link.
	ErrPrevDigestMismatch ErrorCode = "PREV_DIGEST_MISMATCH"
	// ErrDigestMismatch is reported when recomputing an event digest from
	// its id, prevDigest and payload does not reproduce its declared digest:
	// the body (or one of the signed fields) was tampered with.
	ErrDigestMismatch ErrorCode = "DIGEST_MISMATCH"
)

// ChainError describes one integrity failure.
type ChainError struct {
	Code    ErrorCode `json:"code"`
	EventID string    `json:"eventId"`
}

// Report is the audit result. A valid single chain has Valid=true, the events
// ordered from root to tail and the tail digest; otherwise the complete,
// deterministically sorted error list.
type Report struct {
	Valid      bool         `json:"valid"`
	Errors     []ChainError `json:"errors"`
	Events     []Event      `json:"events,omitempty"`
	TailDigest string       `json:"tailDigest,omitempty"`
}

// graphNode is the checker's internal view of one event. It carries every
// field of Event plus a disclosure flag used by the limited-disclosure entry
// point: a withheld payload (Disclosed=false) cannot be recomputed, so its
// own digest is never checked, while every structural and link check still
// applies. The strict audit marks every node disclosed.
type graphNode struct {
	Event
	Disclosed bool
}

// Audit checks a batch of events independently of upload order.
//
// Every detectable defect is collected in one pass. Validation of fields and
// unique ids is the responsibility of the caller (the HTTP layer) so that the
// checker can assume syntactically valid, uniquely identified input.
func Audit(events []Event) Report {
	nodes := make([]graphNode, len(events))
	for i, e := range events {
		nodes[i] = graphNode{Event: e, Disclosed: true}
	}

	ordered, errs := auditNodes(nodes)
	if len(errs) > 0 {
		return Report{Valid: false, Errors: errs}
	}

	orderedEvents := make([]Event, len(ordered))
	for i, n := range ordered {
		orderedEvents[i] = n.Event
	}
	return Report{
		Valid:      true,
		Errors:     []ChainError{},
		Events:     orderedEvents,
		TailDigest: orderedEvents[len(orderedEvents)-1].Digest,
	}
}

// auditNodes runs the complete order-independent check and, when no defect is
// present, returns the single chain rebuilt root-to-tail. Structural checks
// cover every node; the own-digest recomputation covers disclosed nodes only.
func auditNodes(nodes []graphNode) (ordered []graphNode, errs []ChainError) {
	byID := make(map[string]graphNode, len(nodes))
	for _, n := range nodes {
		byID[n.ID] = n
	}

	var roots []graphNode
	children := make(map[string][]string)
	var dangling []graphNode

	for _, n := range nodes {
		if n.ParentID == "" {
			roots = append(roots, n)
			continue
		}
		if _, ok := byID[n.ParentID]; !ok {
			dangling = append(dangling, n)
			continue
		}
		children[n.ParentID] = append(children[n.ParentID], n.ID)
	}

	// Exactly one root.
	switch {
	case len(roots) == 0:
		errs = append(errs, ChainError{Code: ErrNoRoot})
	case len(roots) > 1:
		for _, r := range roots {
			errs = append(errs, ChainError{Code: ErrMultipleRoots, EventID: r.ID})
		}
	}

	// Missing predecessors.
	for _, n := range dangling {
		errs = append(errs, ChainError{Code: ErrMissingParent, EventID: n.ID})
	}

	// Forks: each predecessor may have at most one child.
	for parentID, kids := range children {
		if len(kids) > 1 {
			errs = append(errs, ChainError{Code: ErrFork, EventID: parentID})
		}
	}

	// Digest-level checks. Each digest is recomputed over the event's own
	// declared 32 raw prevDigest bytes, exactly as the digest is defined;
	// link consistency and the root anchor are separate checks.
	for _, n := range nodes {
		e := n.Event
		var prevRaw [32]byte
		if raw, ok := decodeDigest(e.PrevDigest); ok {
			prevRaw = raw
		}
		// Undecodable prevDigest cannot reach here: input syntax is
		// validated upstream; a failure simply degrades into a digest
		// mismatch on recomputation.

		if e.ParentID == "" {
			// The root event must anchor the chain on the all-zero digest.
			if e.PrevDigest != ZeroDigest {
				errs = append(errs, ChainError{Code: ErrRootPrevDigestNotZero, EventID: e.ID})
			}
		} else if parent, parentExists := byID[e.ParentID]; parentExists {
			if e.PrevDigest != parent.Digest {
				errs = append(errs, ChainError{Code: ErrPrevDigestMismatch, EventID: e.ID})
			}
		}
		// When the predecessor is absent the structural MISSING_PARENT error
		// already describes the damage, so no link check is attempted.

		// A withheld payload cannot be hashed: its declared digest is an
		// unverifiable anchor rather than evidence of tampering.
		if n.Disclosed {
			if recomputed := ComputeDigest(e.ID, e.Payload, prevRaw); recomputed != e.Digest {
				errs = append(errs, ChainError{Code: ErrDigestMismatch, EventID: e.ID})
			}
		}
	}

	// Cycle detection over the parent graph (dangling edges excluded).
	// WHITE=unseen, GRAY=on the current DFS stack, BLACK=fully explored.
	const (
		white = 0
		gray  = 1
		black = 2
	)
	color := make(map[string]int, len(nodes))
	var inCycle func(id string)
	inCycle = func(id string) {
		color[id] = gray
		n := byID[id]
		if n.ParentID != "" {
			if _, ok := byID[n.ParentID]; ok {
				switch color[n.ParentID] {
				case white:
					inCycle(n.ParentID)
				case gray:
					// Back edge: walk the stack to mark every cycle member.
					for cur := n.ParentID; ; cur = byID[cur].ParentID {
						errs = append(errs, ChainError{Code: ErrCycle, EventID: cur})
						if cur == id {
							break
						}
					}
				}
			}
		}
		color[id] = black
	}
	for _, n := range nodes {
		if color[n.ID] == white {
			inCycle(n.ID)
		}
	}

	if len(errs) > 0 {
		return nil, dedupeAndSort(errs)
	}

	// No defects: the graph is provably one single chain. Rebuild it from the
	// unique root following the unique child edges, ignoring upload order.
	ordered = make([]graphNode, 0, len(nodes))
	cur := roots[0]
	for {
		ordered = append(ordered, cur)
		kids := children[cur.ID]
		if len(kids) == 0 {
			break
		}
		cur = byID[kids[0]]
	}
	return ordered, nil
}

func decodeDigest(s string) ([32]byte, bool) {
	var raw [32]byte
	if len(s) != 64 {
		return raw, false
	}
	n, err := hex.Decode(raw[:], []byte(s))
	if err != nil || n != 32 {
		return raw, false
	}
	return raw, true
}

// dedupeAndSort returns errors sorted by (code, eventId) with duplicates
// removed. The cycle walk can otherwise report a node more than once when a
// cycle is entered from several DFS trees.
func dedupeAndSort(in []ChainError) []ChainError {
	type key struct {
		code    ErrorCode
		eventID string
	}
	seen := make(map[key]struct{}, len(in))
	out := make([]ChainError, 0, len(in))
	for _, e := range in {
		k := key{e.Code, e.EventID}
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Code != out[j].Code {
			return out[i].Code < out[j].Code
		}
		return out[i].EventID < out[j].EventID
	})
	return out
}
