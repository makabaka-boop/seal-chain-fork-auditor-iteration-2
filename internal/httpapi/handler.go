// Package httpapi exposes the evidence-seal audit service over net/http.
package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"unicode/utf8"

	"sealaudit/internal/audit"
)

const (
	minEvents = 1
	maxEvents = 2000
	// 2000 events of the documented shape stay far below this ceiling; it
	// only protects the parser from oversized or hostile request bodies.
	maxBodyBytes = 16 << 20
)

// Error codes for the 422 request-validation envelope. These are distinct from
// the chain-level audit.ErrorCode values.
const (
	codeMalformedJSON       = "MALFORMED_JSON"
	codeBodyTooLarge        = "BODY_TOO_LARGE"
	codeRequestInvalid      = "REQUEST_VALIDATION_FAILED"
	codeUnsupportedType     = "UNSUPPORTED_MEDIA_TYPE"
	codeInternalServerError = "INTERNAL_SERVER_ERROR"
)

// request is the documented strict request envelope.
type request struct {
	Events []*eventInput `json:"events"`
}

// eventInput uses pointers for required fields so that a missing or null field
// is distinguishable from an empty string.
type eventInput struct {
	ID         *string `json:"id"`
	ParentID   *string `json:"parentId"`
	Payload    *string `json:"payload"`
	PrevDigest *string `json:"prevDigest"`
	Digest     *string `json:"digest"`
}

// limitedRequest is the limited-disclosure envelope. Its field set is the same
// five fields; the only relaxation is that an event's payload may be the
// explicit JSON null (see limitedEventInput).
type limitedRequest struct {
	Events []*limitedEventInput `json:"events"`
}

// handoffRequest is the dual-batch handoff envelope: two independently
// uploaded batches whose events follow the limited-disclosure rules (payload
// may be explicit null).
type handoffRequest struct {
	FirstBatch  []*limitedEventInput `json:"firstBatch"`
	SecondBatch []*limitedEventInput `json:"secondBatch"`
}

// limitedEventInput keeps payload as a RawMessage so that a missing field
// (nil/empty), an explicit JSON null (withheld) and a string (disclosed) are
// three distinguishable cases.
type limitedEventInput struct {
	ID         *string         `json:"id"`
	ParentID   *string         `json:"parentId"`
	Payload    json.RawMessage `json:"payload"`
	PrevDigest *string         `json:"prevDigest"`
	Digest     *string         `json:"digest"`
}

// FieldError pinpoints one rejected field, indexed by the position of the event
// in the request array (0-based). The handoff envelope additionally tags the
// owning batch; the single-batch endpoints leave Batch empty, so their output
// is unchanged.
type FieldError struct {
	Batch  string `json:"batch,omitempty"`
	Index  *int   `json:"index,omitempty"`
	Field  string `json:"field"`
	Reason string `json:"reason"`
}

// invalidResponse is returned with HTTP 422 for every malformed or invalid
// request.
type invalidResponse struct {
	Code   string       `json:"code"`
	Error  string       `json:"error"`
	Fields []FieldError `json:"fields,omitempty"`
}

// NewMux builds the service's HTTP route tree.
func NewMux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /audit", handleAudit)
	// Explicit method-less routes so non-POST callers get 405 instead of
	// being swallowed by the not-found catch-all.
	mux.HandleFunc("/audit", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusMethodNotAllowed, invalidResponse{
			Code:  "METHOD_NOT_ALLOWED",
			Error: "use POST /audit",
		})
	})
	mux.HandleFunc("POST /audit/limited", handleAuditLimited)
	mux.HandleFunc("/audit/limited", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusMethodNotAllowed, invalidResponse{
			Code:  "METHOD_NOT_ALLOWED",
			Error: "use POST /audit/limited",
		})
	})
	mux.HandleFunc("POST /audit/handoff", handleAuditHandoff)
	mux.HandleFunc("/audit/handoff", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusMethodNotAllowed, invalidResponse{
			Code:  "METHOD_NOT_ALLOWED",
			Error: "use POST /audit/handoff",
		})
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusNotFound, invalidResponse{
			Code:  "NOT_FOUND",
			Error: "unknown route; use POST /audit, POST /audit/limited or POST /audit/handoff",
		})
	})
	return mux
}

// handleAudit serves the strict entry point: all five fields are mandatory and
// payload must be a string. Its request and response shapes are unchanged by
// the limited-disclosure feature.
func handleAudit(w http.ResponseWriter, r *http.Request) {
	var req request
	if !decodeEnvelope(w, r, &req) {
		return
	}

	fields := validateStrict(req)
	if len(fields) > 0 {
		writeValidationFailed(w, fields)
		return
	}

	events := make([]audit.Event, len(req.Events))
	for i, in := range req.Events {
		events[i] = audit.Event{
			ID:         *in.ID,
			ParentID:   *in.ParentID,
			Payload:    *in.Payload,
			PrevDigest: *in.PrevDigest,
			Digest:     *in.Digest,
		}
	}

	writeJSON(w, http.StatusOK, audit.Audit(events))
}

// handleAuditLimited serves the limited-disclosure entry point. A payload
// written as explicit null means the body is withheld; it never enters the
// process and is never echoed back.
func handleAuditLimited(w http.ResponseWriter, r *http.Request) {
	var req limitedRequest
	if !decodeEnvelope(w, r, &req) {
		return
	}

	fields := validateLimited(req)
	if len(fields) > 0 {
		writeValidationFailed(w, fields)
		return
	}

	events := limitedEventsFromInputs(req.Events)

	writeJSON(w, http.StatusOK, audit.AuditLimited(events))
}

// handleAuditHandoff serves the dual-batch handoff entry point. The two
// batches are validated independently with the limited-disclosure rules; the
// handoff-anchor and cross-batch id rules are audit conclusions, not request
// errors. Withheld payloads never enter the process and are never echoed.
func handleAuditHandoff(w http.ResponseWriter, r *http.Request) {
	var req handoffRequest
	if !decodeEnvelope(w, r, &req) {
		return
	}

	fields := validateHandoff(req)
	if len(fields) > 0 {
		writeValidationFailed(w, fields)
		return
	}

	writeJSON(w, http.StatusOK, audit.AuditHandoff(audit.HandoffBatches{
		FirstBatch:  limitedEventsFromInputs(req.FirstBatch),
		SecondBatch: limitedEventsFromInputs(req.SecondBatch),
	}))
}

// fieldErrors accumulates request-level field failures, indexed per event.
type fieldErrors []FieldError

func (f *fieldErrors) add(batch string, index int, field, reason string) {
	i := index
	*f = append(*f, FieldError{Batch: batch, Index: &i, Field: field, Reason: reason})
}

func (f *fieldErrors) addTop(batch, field, reason string) {
	*f = append(*f, FieldError{Batch: batch, Field: field, Reason: reason})
}

func (f *fieldErrors) checkID(batch string, index int, id *string, seen map[string]struct{}) {
	switch {
	case id == nil:
		f.add(batch, index, "id", "id is required")
	case *id == "":
		f.add(batch, index, "id", "id must not be empty")
	case len(*id) > 0xffffffff:
		f.add(batch, index, "id", "id length exceeds uint32 range")
	default:
		if _, dup := seen[*id]; dup {
			f.add(batch, index, "id", "id must be unique within the batch")
			return
		}
		seen[*id] = struct{}{}
	}
}

func (f *fieldErrors) checkParent(batch string, index int, parent *string) {
	// parentId marks the root when empty; any other value must resolve to an
	// event (checked by the auditor).
	if parent == nil {
		f.add(batch, index, "parentId", "parentId is required (use an empty string for the root)")
	}
}

func (f *fieldErrors) checkDigestField(batch string, index int, field string, value *string) {
	switch {
	case value == nil:
		f.add(batch, index, field, field+" is required")
	case !isHexDigest(*value):
		f.add(batch, index, field, field+" must be 64 lowercase hexadecimal characters")
	}
}

func validateStrict(req request) []FieldError {
	var fields fieldErrors
	if req.Events == nil {
		fields.addTop("", "events", "events is required and must be an array")
		return fields
	}
	if len(req.Events) < minEvents || len(req.Events) > maxEvents {
		fields.addTop("", "events", "events must contain between 1 and 2000 items")
		return fields
	}
	seen := make(map[string]struct{}, len(req.Events))
	for i, in := range req.Events {
		if in == nil {
			fields.add("", i, "event", "event must be a JSON object")
			continue
		}
		fields.checkID("", i, in.ID, seen)
		fields.checkParent("", i, in.ParentID)
		switch {
		case in.Payload == nil:
			fields.add("", i, "payload", "payload is required")
		case len(*in.Payload) > 0xffffffff:
			fields.add("", i, "payload", "payload length exceeds uint32 range")
		}
		fields.checkDigestField("", i, "prevDigest", in.PrevDigest)
		fields.checkDigestField("", i, "digest", in.Digest)
	}
	return fields
}

func validateLimited(req limitedRequest) []FieldError {
	var fields fieldErrors
	if req.Events == nil {
		fields.addTop("", "events", "events is required and must be an array")
		return fields
	}
	validateLimitedEvents(&fields, "", req.Events)
	return fields
}

// validateLimitedEvents applies the limited-disclosure per-event rules to one
// batch. batch is empty for the single-batch endpoint and "firstBatch" or
// "secondBatch" for the handoff envelope.
func validateLimitedEvents(fields *fieldErrors, batch string, events []*limitedEventInput) {
	if len(events) < minEvents || len(events) > maxEvents {
		fields.addTop(batch, "events", "events must contain between 1 and 2000 items")
		return
	}
	seen := make(map[string]struct{}, len(events))
	for i, in := range events {
		if in == nil {
			fields.add(batch, i, "event", "event must be a JSON object")
			continue
		}
		fields.checkID(batch, i, in.ID, seen)
		fields.checkParent(batch, i, in.ParentID)
		// A missing payload is still a request error; only an explicit null
		// is the documented way to withhold the body.
		switch payload, disclosed, ok := decodeLimitedPayload(in.Payload); {
		case !ok:
			// decodeLimitedPayload records no reason itself; classify here.
			if len(in.Payload) == 0 {
				fields.add(batch, i, "payload", "payload is required (use null to withhold it)")
			} else {
				fields.add(batch, i, "payload", "payload must be a JSON string or null")
			}
		case disclosed && len(payload) > 0xffffffff:
			fields.add(batch, i, "payload", "payload length exceeds uint32 range")
		}
		fields.checkDigestField(batch, i, "prevDigest", in.PrevDigest)
		fields.checkDigestField(batch, i, "digest", in.Digest)
	}
}

// validateHandoff validates both batches independently with the same shape and
// size rules as the single-batch limited endpoint, tagging every field error
// with its owning batch. Cross-batch id disjointness is an audit-level rule
// (reported in the 200 audit response), not a 422 request error.
func validateHandoff(req handoffRequest) []FieldError {
	var fields fieldErrors
	if req.FirstBatch == nil {
		fields.addTop("firstBatch", "firstBatch", "firstBatch is required and must be an array")
	} else {
		validateLimitedEvents(&fields, "firstBatch", req.FirstBatch)
	}
	if req.SecondBatch == nil {
		fields.addTop("secondBatch", "secondBatch", "secondBatch is required and must be an array")
	} else {
		validateLimitedEvents(&fields, "secondBatch", req.SecondBatch)
	}
	return fields
}

// limitedEventsFromInputs converts validated limited-event inputs into audit
// events. Validation must already have guaranteed payload is present as either
// a string or explicit null; null stays Disclosed=false with no body.
func limitedEventsFromInputs(inputs []*limitedEventInput) []audit.LimitedEvent {
	events := make([]audit.LimitedEvent, len(inputs))
	for i, in := range inputs {
		le := audit.LimitedEvent{
			Event: audit.Event{
				ID:         *in.ID,
				ParentID:   *in.ParentID,
				PrevDigest: *in.PrevDigest,
				Digest:     *in.Digest,
			},
		}
		if payload, disclosed, _ := decodeLimitedPayload(in.Payload); disclosed {
			le.Payload = payload
			le.Disclosed = true
		}
		events[i] = le
	}
	return events
}

// decodeLimitedPayload interprets one payload value for the limited entry
// point. Missing (empty raw) or malformed values return ok=false; an explicit
// null returns disclosed=false; a JSON string returns its value. A withheld
// body therefore never surfaces as Go string content anywhere.
func decodeLimitedPayload(raw json.RawMessage) (payload string, disclosed bool, ok bool) {
	if len(raw) == 0 {
		return "", false, false
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return "", false, true
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false, false
	}
	return s, true, true
}

func writeValidationFailed(w http.ResponseWriter, fields []FieldError) {
	writeJSON(w, http.StatusUnprocessableEntity, invalidResponse{
		Code:   codeRequestInvalid,
		Error:  "request failed validation",
		Fields: fields,
	})
}

// decodeEnvelope performs the request-level checks shared by both entry points
// — media type, size, UTF-8, single JSON value, no unknown fields — and
// decodes into v. It returns false after having written the error response.
func decodeEnvelope(w http.ResponseWriter, r *http.Request, v any) bool {
	if ct := r.Header.Get("Content-Type"); ct != "" && ct != "application/json" {
		// Tolerate absent charset; reject clearly non-JSON payloads.
		if media := mediaType(ct); media != "application/json" {
			writeJSON(w, http.StatusUnsupportedMediaType, invalidResponse{
				Code:  codeUnsupportedType,
				Error: "Content-Type must be application/json",
			})
			return false
		}
	}

	body := http.MaxBytesReader(w, r.Body, maxBodyBytes)
	raw, readErr := io.ReadAll(body)
	if readErr != nil {
		var maxErr *http.MaxBytesError
		if errors.As(readErr, &maxErr) {
			writeJSON(w, http.StatusUnprocessableEntity, invalidResponse{
				Code:  codeBodyTooLarge,
				Error: "request body exceeds 16 MiB limit",
			})
			return false
		}
		writeJSON(w, http.StatusBadRequest, invalidResponse{
			Code:  codeMalformedJSON,
			Error: "cannot read request body",
		})
		return false
	}

	// JSON text must itself be valid UTF-8 (RFC 8259); Go's decoder would
	// otherwise silently replace invalid bytes with U+FFFD.
	if !utf8.Valid(raw) {
		writeJSON(w, http.StatusUnprocessableEntity, invalidResponse{
			Code:  codeMalformedJSON,
			Error: "request body must be valid UTF-8 JSON",
		})
		return false
	}

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, invalidResponse{
			Code:  codeMalformedJSON,
			Error: "request body is not a valid events document: " + truncate(err.Error()),
		})
		return false
	}
	// Require a single JSON value: no trailing tokens or data.
	if err := dec.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusUnprocessableEntity, invalidResponse{
			Code:  codeMalformedJSON,
			Error: "request body must contain exactly one JSON object",
		})
		return false
	}
	return true
}

func isHexDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		isDigit := c >= '0' && c <= '9'
		isLowerHex := c >= 'a' && c <= 'f'
		if !isDigit && !isLowerHex {
			return false
		}
	}
	return true
}

func mediaType(contentType string) string {
	for i := 0; i < len(contentType); i++ {
		if contentType[i] == ';' {
			contentType = contentType[:i]
			break
		}
	}
	// Trim leading/trailing whitespace (e.g. "application/json; charset=utf-8").
	start, end := 0, len(contentType)
	for start < end && isSpace(contentType[start]) {
		start++
	}
	for end > start && isSpace(contentType[end-1]) {
		end--
	}
	return contentType[start:end]
}

func isSpace(b byte) bool {
	switch b {
	case ' ', '\t', '\n', '\r':
		return true
	}
	return false
}

func truncate(s string) string {
	const max = 200
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	_ = enc.Encode(v)
}
