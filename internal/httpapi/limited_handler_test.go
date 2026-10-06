package httpapi_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"sealaudit/internal/httpapi"
)

// postLimited sends a body to POST /audit/limited.
func postLimited(t *testing.T, body any) *httptest.ResponseRecorder {
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
	req := httptest.NewRequest(http.MethodPost, "/audit/limited", rdr)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	httpapi.NewMux().ServeHTTP(rec, req)
	return rec
}

// limitedMaps builds the pinned v0..v3 chain; ids in hidden are emitted with
// payload:null (Go nil encodes as explicit JSON null).
func limitedMaps(hidden map[string]bool) []map[string]any {
	out := make([]map[string]any, 4)
	for i := 0; i < 4; i++ {
		id := pinnedLimitedID(i)
		var payload any = pinnedLimitedPayloads[i]
		if hidden[id] {
			payload = nil
		}
		parent := ""
		if i > 0 {
			parent = pinnedLimitedID(i - 1)
		}
		out[i] = map[string]any{
			"id":         id,
			"parentId":   parent,
			"payload":    payload,
			"prevDigest": pinnedLimitedPrevs[i],
			"digest":     pinnedLimitedDigests[i],
		}
	}
	return out
}

// Pinned vectors shared with the audit package tests (independent SHA-256
// vectors over body-0..body-3).
var (
	pinnedLimitedPayloads = []string{"body-0", "body-1", "body-2", "body-3"}
	pinnedLimitedPrevs    = []string{
		strings.Repeat("0", 64),
		"1dd5192560a245aa6df46e3fe561de9842eaec04fa922b770d160bc8aaf0a0b7",
		"99b9cff23861e36f06708e966351f1723d803323d0e3a0d016655a95035c58b8",
		"c59ed192115a7466e2371a6aa23b7b5ddc637d92ea01eae685f6ece69cc46bd9",
	}
	pinnedLimitedDigests = []string{
		"1dd5192560a245aa6df46e3fe561de9842eaec04fa922b770d160bc8aaf0a0b7",
		"99b9cff23861e36f06708e966351f1723d803323d0e3a0d016655a95035c58b8",
		"c59ed192115a7466e2371a6aa23b7b5ddc637d92ea01eae685f6ece69cc46bd9",
		"caebe7a58c8339810ebe10bab9f1b8765a241ae1315a9e1dea4a27c04ea2be9e",
	}
)

func pinnedLimitedID(i int) string {
	return "v" + string(rune('0'+i))
}

func TestLimitedHTTPAllDisclosedVerified(t *testing.T) {
	rec := postLimited(t, map[string]any{"events": limitedMaps(nil)})
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
		if m["status"] != "VERIFIED" {
			t.Fatalf("event %d status %v, want VERIFIED", i, m["status"])
		}
		if m["payload"] != pinnedLimitedPayloads[i] {
			t.Fatalf("event %d payload %v", i, m["payload"])
		}
	}
}

// TestLimitedHTTPHiddenRootMiddleTail exercises all three hiding positions
// end-to-end and asserts no hidden body is ever present, even from input.
func TestLimitedHTTPHiddenRootMiddleTail(t *testing.T) {
	cases := []struct {
		name   string
		hidden string
		want   []string
	}{
		{"root", "v0", []string{"ANCHOR_UNVERIFIED", "ANCHOR_UNVERIFIED", "ANCHOR_UNVERIFIED", "ANCHOR_UNVERIFIED"}},
		{"middle", "v2", []string{"VERIFIED_PREFIX", "VERIFIED_PREFIX", "ANCHOR_UNVERIFIED", "ANCHOR_UNVERIFIED"}},
		{"tail", "v3", []string{"VERIFIED_PREFIX", "VERIFIED_PREFIX", "VERIFIED_PREFIX", "ANCHOR_UNVERIFIED"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Deliberately shuffled upload.
			maps := limitedMaps(map[string]bool{tc.hidden: true})
			maps[0], maps[3] = maps[3], maps[0]
			maps[1], maps[2] = maps[2], maps[1]
			rec := postLimited(t, map[string]any{"events": maps})
			if rec.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
			body := decodeBody(t, rec)
			if body["status"] != "PARTIAL" || body["valid"] != true {
				t.Fatalf("want valid+PARTIAL, got %s", rec.Body.String())
			}
			events := body["events"].([]any)
			for i, ev := range events {
				m := ev.(map[string]any)
				if m["id"] != "v"+string(rune('0'+i)) {
					t.Fatalf("position %d id %v (must rebuild root-to-tail)", i, m["id"])
				}
				if m["status"] != tc.want[i] {
					t.Fatalf("%s position %d status %v, want %s; full %s",
						tc.name, i, m["status"], tc.want[i], rec.Body.String())
				}
				if m["id"] == tc.hidden {
					if m["payload"] != nil {
						t.Fatalf("hidden %s payload must be null, got %v", tc.hidden, m["payload"])
					}
				}
			}
		})
	}
}

// TestLimitedHTTPTamperedDisclosedBody: a disclosed body that does not
// recompute returns only sorted errors, never a chain.
func TestLimitedHTTPTamperedDisclosedBody(t *testing.T) {
	maps := limitedMaps(map[string]bool{"v3": true})
	maps[1]["payload"] = "rewritten"
	rec := postLimited(t, map[string]any{"events": maps})
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	body := decodeBody(t, rec)
	if body["valid"] != false {
		t.Fatalf("want valid=false, got %s", rec.Body.String())
	}
	errs := body["errors"].([]any)
	if len(errs) != 1 {
		t.Fatalf("want exactly one error, got %s", rec.Body.String())
	}
	only := errs[0].(map[string]any)
	if only["code"] != "DIGEST_MISMATCH" || only["eventId"] != "v1" {
		t.Fatalf("want DIGEST_MISMATCH/v1, got %v", only)
	}
	if _, ok := body["events"]; ok {
		t.Fatal("errors response must not include events")
	}
	if _, ok := body["status"]; ok {
		t.Fatal("errors response must not include status")
	}
}

// TestLimitedHTTPForgedLink: bad prevDigest on a disclosed event is rejected
// even though the structure is intact and another event is hidden.
func TestLimitedHTTPForgedLink(t *testing.T) {
	maps := limitedMaps(map[string]bool{"v2": true})
	maps[3]["prevDigest"] = strings.Repeat("e", 64)
	rec := postLimited(t, map[string]any{"events": maps})
	body := decodeBody(t, rec)
	if body["valid"] != false {
		t.Fatalf("forged link must invalidate, got %s", rec.Body.String())
	}
	found := false
	for _, e := range body["errors"].([]any) {
		m := e.(map[string]any)
		if m["code"] == "PREV_DIGEST_MISMATCH" && m["eventId"] == "v3" {
			found = true
		}
	}
	if !found {
		t.Fatalf("want PREV_DIGEST_MISMATCH/v3, got %s", rec.Body.String())
	}
}

// TestLimitedHTTPForkDetected with hidden participants proves hiding does not
// weaken structural checks, and upload order is irrelevant.
func TestLimitedHTTPForkDetected(t *testing.T) {
	maps := limitedMaps(map[string]bool{"v1": true})
	// Repoint v3 at v1 -> v1 forks (v2 and v3).
	maps[3]["parentId"] = "v1"
	// Shuffle.
	maps[0], maps[2] = maps[2], maps[0]
	rec := postLimited(t, map[string]any{"events": maps})
	body := decodeBody(t, rec)
	if body["valid"] != false {
		t.Fatalf("fork must invalidate, got %s", rec.Body.String())
	}
	found := false
	for _, e := range body["errors"].([]any) {
		m := e.(map[string]any)
		if m["code"] == "FORK" && m["eventId"] == "v1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("want FORK/v1, got %s", rec.Body.String())
	}
}

// TestLimitedHTTPNullOnlyAllowedAtLimitedEntry: the strict /audit keeps its
// five mandatory string fields — a null payload is 422 there but accepted here.
func TestLimitedHTTPNullSemantics(t *testing.T) {
	zero := strings.Repeat("0", 64)
	strictNull := `{"events":[{"id":"v0","parentId":"","payload":null,"prevDigest":"` + zero +
		`","digest":"1dd5192560a245aa6df46e3fe561de9842eaec04fa922b770d160bc8aaf0a0b7"}]}`

	recStrict := postAudit(t, strictNull)
	if recStrict.Code != http.StatusUnprocessableEntity {
		t.Fatalf("strict /audit must 422 on null payload, got %d: %s",
			recStrict.Code, recStrict.Body.String())
	}
	sb := decodeBody(t, recStrict)
	if sb["code"] != "REQUEST_VALIDATION_FAILED" {
		t.Fatalf("strict null payload code=%v", sb["code"])
	}

	// Missing payload field (vs explicit null) is still 422 at the limited
	// entry point.
	missing := `{"events":[{"id":"v0","parentId":"","prevDigest":"` + zero +
		`","digest":"1dd5192560a245aa6df46e3fe561de9842eaec04fa922b770d160bc8aaf0a0b7"}]}`
	recMissing := postLimited(t, missing)
	if recMissing.Code != http.StatusUnprocessableEntity {
		t.Fatalf("missing payload must 422 at /audit/limited, got %d: %s",
			recMissing.Code, recMissing.Body.String())
	}

	// Non-string non-null payload is 422 too.
	wrongType := `{"events":[{"id":"v0","parentId":"","payload":123,"prevDigest":"` + zero +
		`","digest":"1dd5192560a245aa6df46e3fe561de9842eaec04fa922b770d160bc8aaf0a0b7"}]}`
	recWrong := postLimited(t, wrongType)
	if recWrong.Code != http.StatusUnprocessableEntity {
		t.Fatalf("numeric payload must 422, got %d: %s", recWrong.Code, recWrong.Body.String())
	}
}

// TestLimitedHTTPStrictFieldRulesShared: unknown fields, bad digests, empty
// ids, null events etc. are rejected identically at the new entry point.
func TestLimitedHTTPStrictFieldRulesShared(t *testing.T) {
	zero := strings.Repeat("0", 64)
	cases := []string{
		`{"events":[]}`,
		`{"events":[{"id":"a","parentId":"","payload":null,"prevDigest":"00","digest":"` + zero + `"}]}`,
		`{"events":[{"id":"","parentId":"","payload":null,"prevDigest":"` + zero + `","digest":"` + zero + `"}]}`,
		`{"events":[null]}`,
		`{"events":[{"id":"a","parentId":"","payload":null,"prevDigest":"` + zero + `","digest":"` + zero + `","x":1}]}`,
		`{"events":[{"id":"a","parentId":"","payload":null,"prevDigest":"` + strings.Repeat("A", 64) + `","digest":"` + zero + `"}]}`,
	}
	for i, body := range cases {
		rec := postLimited(t, body)
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("case %d: want 422, got %d body=%s", i, rec.Code, rec.Body.String())
		}
	}
}

func TestLimitedHTTPMethodAndRouting(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/audit/limited", nil)
	rec := httptest.NewRecorder()
	httpapi.NewMux().ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /audit/limited = %d, want 405", rec.Code)
	}

	// Strict endpoint still refuses non-POST independently.
	req2 := httptest.NewRequest(http.MethodGet, "/audit", nil)
	rec2 := httptest.NewRecorder()
	httpapi.NewMux().ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /audit = %d, want 405", rec2.Code)
	}
}

// TestLimitedHTTPResponseDoesNotEchoHidden checks the literal response body of
// an audit with a hidden event contains no per-event plain "VERIFIED".
func TestLimitedHTTPResponseDoesNotEchoHidden(t *testing.T) {
	maps := limitedMaps(map[string]bool{"v1": true})
	rec := postLimited(t, map[string]any{"events": maps})
	body := rec.Body.String()
	if strings.Contains(body, `"status":"VERIFIED"`) {
		t.Fatalf("no event may be plain VERIFIED with a hidden event: %s", body)
	}
	if !strings.Contains(body, `"status":"PARTIAL"`) {
		t.Fatalf("chain must be PARTIAL: %s", body)
	}
	if !strings.Contains(body, `"payload":null`) {
		t.Fatalf("hidden payload must render null: %s", body)
	}
}
