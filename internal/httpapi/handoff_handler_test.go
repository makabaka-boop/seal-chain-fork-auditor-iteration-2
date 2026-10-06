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

func postHandoff(t *testing.T, body any) *responseEnvelope {
	t.Helper()
	var raw []byte
	switch v := body.(type) {
	case string:
		raw = []byte(v)
	default:
		var err error
		raw, err = json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/audit/handoff", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	httpapi.NewMux().ServeHTTP(rec, req)
	return &responseEnvelope{rec, decodeBody(t, rec)}
}

type responseEnvelope struct {
	Recorder *httptest.ResponseRecorder
	Body     map[string]any
}

func handoffMaps(firstHidden, secondHidden map[string]bool) map[string]any {
	return map[string]any{
		"firstBatch":  map[string]any{"events": limitedMaps(firstHidden)},
		"secondBatch": map[string]any{"events": secondBatchMaps(secondHidden)},
	}
}

func secondBatchMaps(hidden map[string]bool) []map[string]any {
	payloads := []string{"hand-0", "hand-1"}
	prevs := []string{
		pinnedLimitedDigests[3],
		"f0309276c4cd9989ec1d9d6a0b1c92e2efbe51a88a1684f4559f8c332e4a5eea",
	}
	digests := []string{
		"f0309276c4cd9989ec1d9d6a0b1c92e2efbe51a88a1684f4559f8c332e4a5eea",
		"a3592824bce426abfb8e53fb2f94635d152f5582e29c457f1ca6e3e0e007dd0d",
	}
	out := make([]map[string]any, 2)
	for i := 0; i < 2; i++ {
		id := "h" + string(rune('0'+i))
		var payload any = payloads[i]
		if hidden[id] {
			payload = nil
		}
		parent := ""
		if i > 0 {
			parent = "h" + string(rune('0'+i-1))
		}
		out[i] = map[string]any{
			"id":         id,
			"parentId":   parent,
			"payload":    payload,
			"prevDigest": prevs[i],
			"digest":     digests[i],
		}
	}
	return out
}

func TestHandoffHTTPVerified(t *testing.T) {
	body := handoffMaps(nil, nil)
	// Deliberately scramble both uploads.
	first := body["firstBatch"].(map[string]any)["events"].([]map[string]any)
	second := body["secondBatch"].(map[string]any)["events"].([]map[string]any)
	first[0], first[3] = first[3], first[0]
	second[0], second[1] = second[1], second[0]

	rec := postHandoff(t, body)
	if rec.Recorder.Code != http.StatusOK || rec.Body["valid"] != true || rec.Body["status"] != "VERIFIED" {
		t.Fatalf("want 200 valid VERIFIED, got %d %s", rec.Recorder.Code, rec.Recorder.Body.String())
	}
	ids := []string{"v0", "v1", "v2", "v3", "h0", "h1"}
	for i, ev := range rec.Body["events"].([]any) {
		m := ev.(map[string]any)
		if m["id"] != ids[i] || m["status"] != "VERIFIED" {
			t.Fatalf("position %d = %#v, want %s/VERIFIED", i, m, ids[i])
		}
	}
}

func TestHandoffHTTPTrustPropagationAndNoHiddenEcho(t *testing.T) {
	rec := postHandoff(t, handoffMaps(map[string]bool{"v2": true}, map[string]bool{"h1": true}))
	if rec.Recorder.Code != http.StatusOK || rec.Body["status"] != "PARTIAL" {
		t.Fatalf("want PARTIAL, got %d %s", rec.Recorder.Code, rec.Recorder.Body.String())
	}
	want := []string{
		"VERIFIED_PREFIX", "VERIFIED_PREFIX", "ANCHOR_UNVERIFIED",
		"ANCHOR_UNVERIFIED", "ANCHOR_UNVERIFIED", "ANCHOR_UNVERIFIED",
	}
	for i, ev := range rec.Body["events"].([]any) {
		m := ev.(map[string]any)
		if m["status"] != want[i] {
			t.Fatalf("%s status=%v want %s", m["id"], m["status"], want[i])
		}
	}
	text := rec.Recorder.Body.String()
	if strings.Contains(text, "WITHHELD") || !strings.Contains(text, `"payload":null`) {
		t.Fatalf("hidden payloads must render null only: %s", text)
	}
}

func TestHandoffHTTPAnchorMismatch(t *testing.T) {
	body := handoffMaps(nil, nil)
	second := body["secondBatch"].(map[string]any)["events"].([]map[string]any)
	fakeAnchor := strings.Repeat("f", 64)
	fakeRawBytes, err := hex.DecodeString(fakeAnchor)
	if err != nil {
		t.Fatal(err)
	}
	var fakeRaw [32]byte
	copy(fakeRaw[:], fakeRawBytes)
	second[0]["prevDigest"] = fakeAnchor
	second[0]["digest"] = audit.ComputeDigest("h0", "hand-0", fakeRaw)
	rec := postHandoff(t, body)
	if rec.Recorder.Code != http.StatusOK || rec.Body["valid"] != false {
		t.Fatalf("want audit finding, got %d %s", rec.Recorder.Code, rec.Recorder.Body.String())
	}
	found := false
	for _, e := range rec.Body["errors"].([]any) {
		m := e.(map[string]any)
		if m["code"] == "HANDOFF_DIGEST_MISMATCH" && m["eventId"] == "h0" {
			found = true
		}
	}
	if !found {
		t.Fatalf("want handoff mismatch h0, got %s", rec.Recorder.Body.String())
	}
	if _, ok := rec.Body["events"]; ok {
		t.Fatal("invalid handoff must not return a chain")
	}
}

func TestHandoffHTTPCrossBatchDuplicateID(t *testing.T) {
	body := handoffMaps(nil, nil)
	second := body["secondBatch"].(map[string]any)["events"].([]map[string]any)
	second[1]["id"] = "v3"
	// Recompute the declared digest so only the cross-batch id collision is
	// responsible for this event's rejection.
	prev, err := hex.DecodeString(second[1]["prevDigest"].(string))
	if err != nil {
		t.Fatal(err)
	}
	var raw [32]byte
	copy(raw[:], prev)
	second[1]["digest"] = audit.ComputeDigest("v3", "hand-1", raw)

	rec := postHandoff(t, body)
	found := false
	for _, e := range rec.Body["errors"].([]any) {
		m := e.(map[string]any)
		if m["code"] == "CROSS_BATCH_DUPLICATE_ID" && m["eventId"] == "v3" {
			found = true
		}
	}
	if !found {
		t.Fatalf("want cross-batch duplicate, got %s", rec.Recorder.Body.String())
	}
}

func TestHandoffHTTPValidation(t *testing.T) {
	zero := strings.Repeat("0", 64)
	cases := []string{
		`{"firstBatch":{"events":[]},"secondBatch":{"events":[]}}`,
		`{"firstBatch":{"events":[{"id":"a","parentId":"","payload":null,"prevDigest":"` + zero + `","digest":"` + zero + `"}]}}`,
		`{"firstBatch":{"events":[{"id":"a","parentId":"","payload":1,"prevDigest":"` + zero + `","digest":"` + zero + `"}]},"secondBatch":{"events":[{"id":"b","parentId":"","payload":null,"prevDigest":"` + zero + `","digest":"` + zero + `"}]}}`,
		`{"firstBatch":{"events":[{"id":"","parentId":"","payload":null,"prevDigest":"` + zero + `","digest":"` + zero + `"}]},"secondBatch":{"events":[{"id":"b","parentId":"","payload":null,"prevDigest":"` + zero + `","digest":"` + zero + `"}]}}`,
	}
	for i, body := range cases {
		rec := postHandoff(t, body)
		if rec.Recorder.Code != http.StatusUnprocessableEntity {
			t.Fatalf("case %d: want 422, got %d %s", i, rec.Recorder.Code, rec.Recorder.Body.String())
		}
	}
}

func TestHandoffHTTPRoutingDoesNotChangeExistingEntries(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/audit/handoff", nil)
	rec := httptest.NewRecorder()
	httpapi.NewMux().ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET handoff = %d, want 405", rec.Code)
	}

	// Existing endpoints retain their method handling.
	req = httptest.NewRequest(http.MethodDelete, "/audit", nil)
	rec = httptest.NewRecorder()
	httpapi.NewMux().ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("DELETE /audit = %d, want 405", rec.Code)
	}
	req = httptest.NewRequest(http.MethodDelete, "/audit/limited", nil)
	rec = httptest.NewRecorder()
	httpapi.NewMux().ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("DELETE /audit/limited = %d, want 405", rec.Code)
	}
}
