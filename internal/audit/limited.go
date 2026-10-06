package audit

// LimitedEvent is one evidence-seal record handed to the limited-disclosure
// audit. Its shape and the raw digest byte definition are exactly those of
// Event; the only difference is semantic.
//
// When Disclosed is false the caller must set Payload to the empty string:
// the JSON entry point encodes a withheld body as an explicit null, and the
// payload never enters this process. Its declared digest cannot be recomputed
// and is therefore treated as an unverifiable anchor, never as proof.
type LimitedEvent struct {
	Event
	Disclosed bool `json:"-"`
}

// ChainStatus is the whole-chain verdict of a limited-disclosure audit.
type ChainStatus string

const (
	// ChainVerified means every event was disclosed and every digest was
	// recomputed byte-for-byte: the chain is fully trustworthy.
	ChainVerified ChainStatus = "VERIFIED"
	// ChainPartial means the structure is one intact chain and every
	// disclosed event recomputes, but at least one payload was withheld, so
	// the chain cannot be claimed fully verified.
	ChainPartial ChainStatus = "PARTIAL"
)

// EventStatus is the per-event verdict of a limited-disclosure audit.
type EventStatus string

const (
	// StatusVerified marks an event in a fully disclosed, fully recomputed
	// chain.
	StatusVerified EventStatus = "VERIFIED"
	// StatusVerifiedPrefix marks an event in the contiguous root-to-tail run
	// before the first withheld payload: its body and every link behind it
	// were recomputed.
	StatusVerifiedPrefix EventStatus = "VERIFIED_PREFIX"
	// StatusAnchorUnverified marks the first withheld event and everything
	// after it: even a locally recomputable event past the first hidden body
	// is only anchored on an unverifiable digest, never proven.
	StatusAnchorUnverified EventStatus = "ANCHOR_UNVERIFIED"
)

// LimitedEventResult is one rebuilt event in a limited-disclosure report. The
// five seal fields keep their original meaning; Payload serializes back to
// null when the body was withheld, so undisclosed content is never echoed.
type LimitedEventResult struct {
	ID         string      `json:"id"`
	ParentID   string      `json:"parentId"`
	Payload    *string     `json:"payload"`
	PrevDigest string      `json:"prevDigest"`
	Digest     string      `json:"digest"`
	Status     EventStatus `json:"status"`
}

// LimitedReport is the limited-disclosure audit result. As with the strict
// audit, any structural defect or disclosed-digest defect yields only the
// deterministically sorted error list and no chain.
type LimitedReport struct {
	Valid      bool                 `json:"valid"`
	Status     ChainStatus          `json:"status,omitempty"`
	Errors     []ChainError         `json:"errors"`
	Events     []LimitedEventResult `json:"events,omitempty"`
	TailDigest string               `json:"tailDigest,omitempty"`
}

// AuditLimited checks a batch in which any payload may be explicitly withheld
// (Disclosed=false, Payload ignored). The structural rules are identical to
// Audit: unique root, resolvable predecessors, no fork and no cycle, root
// anchor all-zero, and every prevDigest equal to the parent's declared
// digest. Own digests are recomputed byte-for-byte for disclosed events only.
//
// When the structure is one intact chain and all disclosed digests match, the
// order is rebuilt from the graph. The run up to (but excluding) the first
// withheld event is VERIFIED_PREFIX; from that event on every event is
// ANCHOR_UNVERIFIED, even if its own body would recompute. With no withheld
// event the whole chain is VERIFIED.
func AuditLimited(events []LimitedEvent) LimitedReport {
	nodes := make([]graphNode, len(events))
	for i, le := range events {
		nodes[i] = graphNode{Event: le.Event, Disclosed: le.Disclosed}
	}

	ordered, errs := auditNodes(nodes)
	if len(errs) > 0 {
		return LimitedReport{Valid: false, Errors: errs}
	}

	// Locate the first withheld event in the rebuilt root-to-tail order.
	firstHidden := -1
	for i, n := range ordered {
		if !n.Disclosed {
			firstHidden = i
			break
		}
	}

	results := make([]LimitedEventResult, len(ordered))
	for i, n := range ordered {
		var status EventStatus
		switch {
		case firstHidden == -1:
			status = StatusVerified
		case i < firstHidden:
			status = StatusVerifiedPrefix
		default:
			status = StatusAnchorUnverified
		}
		res := LimitedEventResult{
			ID:         n.ID,
			ParentID:   n.ParentID,
			PrevDigest: n.PrevDigest,
			Digest:     n.Digest,
			Status:     status,
		}
		if n.Disclosed {
			payload := n.Payload
			res.Payload = &payload
		} // withheld: Payload stays nil and serializes as null; no body echoed.
		results[i] = res
	}

	status := ChainVerified
	if firstHidden != -1 {
		status = ChainPartial
	}
	return LimitedReport{
		Valid:      true,
		Status:     status,
		Errors:     []ChainError{},
		Events:     results,
		TailDigest: ordered[len(ordered)-1].Digest,
	}
}
