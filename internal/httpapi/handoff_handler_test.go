package httpapi_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"sealaudit/internal/audit"
	"sealaudit/internal/httpapi"
)

// Pinned vectors shared with the audit package handoff tests (independent
// SHA-256 vectors over handoff-0..handoff-3). Batch split is after h1.
var (
	pinnedHandoffPayloads = []string{"handoff-0", "handoff-1", "handoff-2", "handoff-3"}
	pinnedHandoffPrevs    = []string{
		strings.Repeat("0", 64),
		"87a00f7a3c50463eacf0994c92e24a125d00195586e910b02ed8a3af13e7efaa",
		"e85518ae3aebdaa8d6a6f30b14d114eb300ee2707a46e9e4aaf1ea1d36350fc4",
		"741832b4b8e4b6846ca8a55b7abdcbb68ce68e5abd853b857adadc20b9226a6c",
	}
	pinnedHandoffDigests = []string{
		"87a00f7a3c50463eacf0994c92e24a125d00195586e910b02ed8a3af13e7efaa",
		"e85518ae3aebdaa8d6a6f30b14d114eb300ee2707a46e9e4aaf1ea1d36350fc4",
		"741832b4b8e4b6846ca8a55b7abdcbb68ce68e5abd853b857adadc20b9226a6c",
		"65c676c54e657a22739ff531985f275401e3be502ee71624855ece85a72c10c5",
	}
)

func handoffID(i int) string { return "h" + string(rune('0'+i)) }

// handoffMaps builds the two pinned batches. hidden ids render payload:null;
// each batch is returned shuffled to prove upload order is irrelevant.
func handoffMaps(hidden map[string]bool) (first, second []map[string]any) {
	event := func(i int) map[string]any {
		id := handoffID(i)
		var payload any = pinnedHandoffPayloads[i]
		if hidden[id] {
			payload = nil
		}
		parent := ""
		// Parent only links inside the same batch; h2 is batch 2's root.
		if i != 0 && i != 2 {
			parent = handoffID(i - 1)
		}
		return map[string]any{
			"id":         id,
			"parentId":   parent,
			"payload":    payload,
			"prevDigest": pinnedHandoffPrevs[i],
			"digest":     pinnedHandoffDigests[i],
		}
	}
	first = []map[string]any{event(1), event(0)} // shuffled
	second = []map[string]any{event(3), event(2)}
	return first, second
}

func postHandoff(t *testing.T, body any) *httptest.ResponseRecorder {
	t.Helper()
	var rdr *bytes.Reader
	switch v := body.(type) {
	case string:
		rdr = bytes.NewReader([]byte(v))
	case []byte:
		rdr = bytes.NewReader(v)
	default:
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		rdr = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(http.MethodPost, "/audit/handoff", rdr)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	httpapi.NewMux().ServeHTTP(rec, req)
	return rec
}

func TestHandoffHTTPVerifiedAcrossShuffledBatches(t *testing.T) {
	first, second := handoffMaps(nil)
	rec := postHandoff(t, map[string]any{"firstBatch": first, "secondBatch": second})
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	body := decodeBody(t, rec)
	if body["valid"] != true || body["status"] != "VERIFIED" {
		t.Fatalf("want valid+VERIFIED, got %s", rec.Body.String())
	}
	events := body["events"].([]any)
	for i, ev := range events {
		m := ev.(map[string]any)
		if m["id"] != handoffID(i) {
			t.Fatalf("position %d id %v, want %s (spliced graph rebuild)", i, m["id"], handoffID(i))
		}
		if m["status"] != "VERIFIED" {
			t.Fatalf("event %d status %v, want VERIFIED", i, m["status"])
		}
		if m["payload"] != pinnedHandoffPayloads[i] {
			t.Fatalf("event %d payload %v", i, m["payload"])
		}
	}
	if body["tailDigest"] != pinnedHandoffDigests[3] {
		t.Fatalf("tailDigest %v", body["tailDigest"])
	}
}

// TestHandoffHTTPAnchorMismatch: batch 2's root prevDigest not equal to batch
// 1's rebuilt tail returns only the sorted audit errors and no chain.
func TestHandoffHTTPAnchorMismatch(t *testing.T) {
	first, second := handoffMaps(nil)
	// h2 is second[1] after the shuffle used by handoffMaps.
	for _, m := range second {
		if m["id"] == "h2" {
			m["prevDigest"] = strings.Repeat("f", 64)
		}
	}
	rec := postHandoff(t, map[string]any{"firstBatch": first, "secondBatch": second})
	if rec.Code != http.StatusOK {
		t.Fatalf("audit conclusions stay HTTP 200, got %d: %s", rec.Code, rec.Body.String())
	}
	body := decodeBody(t, rec)
	if body["valid"] != false {
		t.Fatalf("want valid=false, got %s", rec.Body.String())
	}
	found := false
	for _, e := range body["errors"].([]any) {
		m := e.(map[string]any)
		if m["code"] == "HANDOFF_ANCHOR_MISMATCH" && m["eventId"] == "h2" {
			found = true
		}
	}
	if !found {
		t.Fatalf("want HANDOFF_ANCHOR_MISMATCH/h2, got %s", rec.Body.String())
	}
	if _, ok := body["events"]; ok {
		t.Fatal("errors response must not include events")
	}
	if _, ok := body["status"]; ok {
		t.Fatal("errors response must not include status")
	}
}

// TestHandoffHTTPCrossBatchDuplicate: an id shared by both batches is an audit
// error, while an id duplicated only inside one batch stays a 422 (the two
// uniqueness levels must not be conflated).
func TestHandoffHTTPCrossBatchDuplicate(t *testing.T) {
	first, _ := handoffMaps(nil)
	// Rebuild batch 2 as a single internally consistent root reusing h1. Its
	// digest is recomputed for id "h1" over the real first-batch tail so the
	// only defect is the cross-batch duplicate.
	tailRaw := func() [32]byte {
		raw, err := hex.DecodeString(pinnedHandoffDigests[1])
		if err != nil {
			t.Fatal(err)
		}
		var out [32]byte
		copy(out[:], raw)
		return out
	}()
	duplicate := map[string]any{
		"id":         "h1",
		"parentId":   "",
		"payload":    "handoff-2",
		"prevDigest": pinnedHandoffDigests[1],
		"digest":     audit.ComputeDigest("h1", "handoff-2", tailRaw),
	}
	rec := postHandoff(t, map[string]any{"firstBatch": first, "secondBatch": []any{duplicate}})
	if rec.Code != http.StatusOK {
		t.Fatalf("cross-batch duplicate is an audit error (200), got %d: %s", rec.Code, rec.Body.String())
	}
	body := decodeBody(t, rec)
	errs := body["errors"].([]any)
	if len(errs) != 1 {
		t.Fatalf("want exactly one error (the cross-batch duplicate), got %s", rec.Body.String())
	}
	found := false
	for _, e := range errs {
		m := e.(map[string]any)
		if m["code"] == "DUPLICATE_ID_ACROSS_BATCHES" && m["eventId"] == "h1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("want DUPLICATE_ID_ACROSS_BATCHES/h1, got %s", rec.Body.String())
	}
}

// TestHandoffHTTPHiddenTrustPropagation: a withheld body at the first-batch
// tail makes the fully disclosed second batch inherit ANCHOR_UNVERIFIED, and
// the hidden body never appears in the response.
func TestHandoffHTTPHiddenTrustPropagation(t *testing.T) {
	first, second := handoffMaps(map[string]bool{"h1": true})
	rec := postHandoff(t, map[string]any{"firstBatch": first, "secondBatch": second})
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	body := decodeBody(t, rec)
	if body["valid"] != true || body["status"] != "PARTIAL" {
		t.Fatalf("want valid+PARTIAL, got %s", rec.Body.String())
	}
	want := []string{"VERIFIED_PREFIX", "ANCHOR_UNVERIFIED", "ANCHOR_UNVERIFIED", "ANCHOR_UNVERIFIED"}
	for i, ev := range body["events"].([]any) {
		m := ev.(map[string]any)
		if m["id"] != handoffID(i) {
			t.Fatalf("position %d id %v", i, m["id"])
		}
		if m["status"] != want[i] {
			t.Fatalf("%s status %v, want %s; full %s", m["id"], m["status"], want[i], rec.Body.String())
		}
	}
	if strings.Contains(rec.Body.String(), `"payload":"handoff-1"`) {
		t.Fatalf("hidden first-batch tail body must not be echoed: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"payload":null`) {
		t.Fatalf("hidden event must render payload:null: %s", rec.Body.String())
	}
}

// TestHandoffHTTPRequestValidation covers the handoff envelope's own 422 rules:
// both batches required, per-event rules shared with /audit/limited, and field
// errors tagged with their owning batch.
func TestHandoffHTTPRequestValidation(t *testing.T) {
	zero := strings.Repeat("0", 64)
	cases := []struct {
		name  string
		body  string
		batch string
		field string
	}{
		{"missing second batch",
			`{"firstBatch":[{"id":"h0","parentId":"","payload":"x","prevDigest":"` + zero + `","digest":"` + zero + `"}]}`,
			"secondBatch", "secondBatch"},
		{"empty first batch", `{"firstBatch":[],"secondBatch":[{"id":"h2","parentId":"","payload":null,"prevDigest":"` + zero + `","digest":"` + zero + `"}]}`,
			"firstBatch", "events"},
		{"bad digest in first batch",
			`{"firstBatch":[{"id":"h0","parentId":"","payload":"x","prevDigest":"00","digest":"` + zero + `"}],
			   "secondBatch":[{"id":"h2","parentId":"","payload":null,"prevDigest":"` + zero + `","digest":"` + zero + `"}]}`,
			"firstBatch", "prevDigest"},
		{"missing payload field in second batch",
			`{"firstBatch":[{"id":"h0","parentId":"","payload":"x","prevDigest":"` + zero + `","digest":"` + zero + `"}],
			   "secondBatch":[{"id":"h2","parentId":"","prevDigest":"` + zero + `","digest":"` + zero + `"}]}`,
			"secondBatch", "payload"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := postHandoff(t, tc.body)
			if rec.Code != http.StatusUnprocessableEntity {
				t.Fatalf("want 422, got %d: %s", rec.Code, rec.Body.String())
			}
			body := decodeBody(t, rec)
			if body["code"] != "REQUEST_VALIDATION_FAILED" {
				t.Fatalf("code=%v body=%s", body["code"], rec.Body.String())
			}
			matched := false
			for _, fe := range body["fields"].([]any) {
				m := fe.(map[string]any)
				if m["batch"] == tc.batch && m["field"] == tc.field {
					matched = true
				}
			}
			if !matched {
				t.Fatalf("want a field error batch=%s field=%s, got %s", tc.batch, tc.field, rec.Body.String())
			}
		})
	}
}

// TestHandoffHTTPInBatchDuplicateStill422 proves per-batch uniqueness remains a
// request error distinct from cross-batch duplicate ids.
func TestHandoffHTTPInBatchDuplicateStill422(t *testing.T) {
	zero := strings.Repeat("0", 64)
	evt := func(id string) string {
		return `{"id":"` + id + `","parentId":"","payload":null,"prevDigest":"` + zero + `","digest":"` + zero + `"}`
	}
	body := `{"firstBatch":[` + evt("h0") + `,` + evt("h0") + `],
	          "secondBatch":[` + evt("h2") + `]}`
	rec := postHandoff(t, body)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("in-batch duplicate id must stay 422, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHandoffHTTPMethodAndRouting keeps method gating consistent with the
// existing endpoints.
func TestHandoffHTTPMethodAndRouting(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/audit/handoff", nil)
	rec := httptest.NewRecorder()
	httpapi.NewMux().ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /audit/handoff = %d, want 405", rec.Code)
	}

	// The original two entry points are unchanged.
	if postAudit(t, `{"events":[]}`).Code != http.StatusUnprocessableEntity {
		t.Fatal("POST /audit must keep its original validation behavior")
	}
	if postLimited(t, `{"events":[]}`).Code != http.StatusUnprocessableEntity {
		t.Fatal("POST /audit/limited must keep its original validation behavior")
	}
}
