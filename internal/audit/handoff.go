package audit

// HandoffEvent is one evidence-seal record in a dual-batch handoff audit. It
// is exactly LimitedEvent with a different name: each batch keeps the same
// five seal fields, the same digest byte definition and the same payload
// hiding rule (Disclosed=false, payload never inspected or echoed).
type HandoffEvent = LimitedEvent

// HandoffBatches is the two independently uploaded, individually unordered
// uploads of an inter-museum transfer: FirstBatch starts the chain on the
// all-zero root anchor; SecondBatch has no in-batch parent for its root and
// must continue exactly at the first batch's rebuilt tail.
type HandoffBatches struct {
	FirstBatch  []HandoffEvent
	SecondBatch []HandoffEvent
}

// HandoffReport is the dual-batch handoff audit result. As with the two
// single-batch entry points, any defect yields only the deterministically
// sorted error list and no splice: Events, Status and TailDigest are omitted.
//
// On success Events is the single rebuilt chain across both batches
// (first-batch root through second-batch tail) with the same per-event trust
// statuses as the limited-disclosure audit; a withheld body anywhere in the
// first batch propagates ANCHOR_UNVERIFIED into the whole second batch, since
// the handoff anchor itself was never recomputed.
type HandoffReport struct {
	Valid      bool                 `json:"valid"`
	Status     ChainStatus          `json:"status,omitempty"`
	Errors     []ChainError         `json:"errors"`
	Events     []LimitedEventResult `json:"events,omitempty"`
	TailDigest string               `json:"tailDigest,omitempty"`
}

// AuditHandoff proves that two separately uploaded, individually unordered
// batches form one continuous evidence chain.
//
// Each batch is checked with exactly the in-batch rules of AuditLimited:
// unique root, resolvable predecessors, no fork and no cycle, own digests
// recomputed byte-for-byte for disclosed events only. The first batch's root
// must anchor on the all-zero digest; the second batch's root has no in-batch
// parent, and instead its prevDigest must equal the first batch's rebuilt
// tail digest. The two batches must also be disjoint in event ids.
//
// In-batch checks, the cross-batch duplicate-id check and the handoff-anchor
// check are all part of the same audit: every defect is collected and the
// result is the single list sorted by (code, eventId). When the first batch
// is itself invalid its tail digest does not exist, so the handoff-anchor
// comparison is undefined and skipped (every second-batch check still runs).
// With any defect no splice is returned.
//
// Trust propagation follows the limited-disclosure rule over the concatenated
// root-to-tail order: only when every event from the first batch's root to
// the second batch's tail is disclosed and recomputed is the result VERIFIED;
// a withheld body in the first batch means even a fully disclosed second
// batch stays PARTIAL with every event from the first hidden one onward
// marked ANCHOR_UNVERIFIED.
func AuditHandoff(batches HandoffBatches) HandoffReport {
	firstNodes := make([]graphNode, len(batches.FirstBatch))
	for i, e := range batches.FirstBatch {
		firstNodes[i] = graphNode{Event: e.Event, Disclosed: e.Disclosed}
	}
	secondNodes := make([]graphNode, len(batches.SecondBatch))
	for i, e := range batches.SecondBatch {
		secondNodes[i] = graphNode{Event: e.Event, Disclosed: e.Disclosed}
	}

	// Cross-batch id disjointness is a handoff-level rule and is checked
	// regardless of what either batch looks like internally.
	var crossErrs []ChainError
	firstIDs := make(map[string]struct{}, len(firstNodes))
	for _, n := range firstNodes {
		firstIDs[n.ID] = struct{}{}
	}
	for _, n := range secondNodes {
		if _, dup := firstIDs[n.ID]; dup {
			crossErrs = append(crossErrs, ChainError{Code: ErrDuplicateIDAcrossBatches, EventID: n.ID})
		}
	}

	firstOrdered, firstErrs := auditNodes(firstNodes, zeroAnchor{})

	// The second batch anchors on the first batch's rebuilt tail when that
	// exists; with an invalid first batch there is no digest to compare
	// against, so its root-anchor check is skipped rather than guessed.
	var secondAnchor rootAnchor
	var firstTail string
	if len(firstErrs) == 0 {
		firstTail = firstOrdered[len(firstOrdered)-1].Digest
		secondAnchor = tailAnchor{digest: firstTail}
	} else {
		secondAnchor = absentAnchor{}
	}
	secondOrdered, secondErrs := auditNodes(secondNodes, secondAnchor)

	errs := dedupeAndSort(append(append(crossErrs, firstErrs...), secondErrs...))
	if len(errs) > 0 {
		return HandoffReport{Valid: false, Errors: errs}
	}

	combined := append(append(make([]graphNode, 0, len(firstOrdered)+len(secondOrdered)),
		firstOrdered...), secondOrdered...)
	return HandoffReport{
		Valid:      true,
		Status:     chainStatusFor(combined),
		Errors:     []ChainError{},
		Events:     buildLimitedResults(combined),
		TailDigest: secondOrdered[len(secondOrdered)-1].Digest,
	}
}
