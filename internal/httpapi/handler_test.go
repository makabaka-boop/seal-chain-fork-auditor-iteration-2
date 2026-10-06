package httpapi_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"sealaudit/internal/audit"
	"sealaudit/internal/httpapi"
)

// chainMaps builds a cryptographically consistent chain, root-to-tail order.
func chainMaps(n int) []map[string]string {
	out := make([]map[string]string, n)
	prev := audit.ZeroDigest
	var prevRaw [32]byte
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("evt-%d", i)
		payload := fmt.Sprintf("p-%d", i)
		digest := audit.ComputeDigest(id, payload, prevRaw)
		parentID := ""
		if i > 0 {
			parentID = out[i-1]["id"]
		}
		out[i] = map[string]string{
			"id":         id,
			"parentId":   parentID,
			"payload":    payload,
			"prevDigest": prev,
			"digest":     digest,
		}
		prev = digest
		raw, err := hex.DecodeString(digest)
		if err != nil {
			panic(err)
		}
		copy(prevRaw[:], raw)
	}
	return out
}

func postAudit(t *testing.T, body any) *httptest.ResponseRecorder {
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
	req := httptest.NewRequest(http.MethodPost, "/audit", rdr)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	httpapi.NewMux().ServeHTTP(rec, req)
	return rec
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("response is not JSON (%q): %v", rec.Body.String(), err)
	}
	return out
}

func TestPostAuditValid(t *testing.T) {
	events := chainMaps(4)
	// Upload in reverse, proving the service does not rely on input order.
	for i, j := 0, len(events)-1; i < j; i, j = i+1, j-1 {
		events[i], events[j] = events[j], events[i]
	}
	rec := postAudit(t, map[string]any{"events": events})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	body := decodeBody(t, rec)
	if body["valid"] != true {
		t.Fatalf("expected valid=true, got %s", rec.Body.String())
	}
	gotEvents := body["events"].([]any)
	if len(gotEvents) != 4 {
		t.Fatalf("want 4 ordered events, got %d", len(gotEvents))
	}
	for i, ev := range gotEvents {
		m := ev.(map[string]any)
		if m["id"] != fmt.Sprintf("evt-%d", i) {
			t.Fatalf("position %d = %v, want evt-%d (root-to-tail)", i, m["id"], i)
		}
	}
	if body["tailDigest"] != chainMaps(4)[3]["digest"] {
		t.Fatalf("wrong tailDigest: %v", body["tailDigest"])
	}
}

func TestPostAuditBodyTamper(t *testing.T) {
	events := chainMaps(3)
	events[1]["payload"] = "rewritten"
	rec := postAudit(t, map[string]any{"events": events})
	if rec.Code != http.StatusOK {
		t.Fatalf("audit findings must return 200, got %d", rec.Code)
	}
	body := decodeBody(t, rec)
	if body["valid"] != false {
		t.Fatalf("expected valid=false, got %s", rec.Body.String())
	}
	errs := body["errors"].([]any)
	if len(errs) != 1 {
		t.Fatalf("want exactly one error, got %s", rec.Body.String())
	}
	only := errs[0].(map[string]any)
	if only["code"] != "DIGEST_MISMATCH" || only["eventId"] != "evt-1" {
		t.Fatalf("want DIGEST_MISMATCH/evt-1, got %v", only)
	}
	if _, ok := body["events"]; ok {
		t.Fatal("invalid chain must not include events")
	}
	if _, ok := body["tailDigest"]; ok {
		t.Fatal("invalid chain must not include tailDigest")
	}
}

func TestPostAuditFork(t *testing.T) {
	events := chainMaps(2) // evt-0 <- evt-1
	raw, err := hex.DecodeString(events[0]["digest"])
	if err != nil {
		t.Fatal(err)
	}
	var prevRaw [32]byte
	copy(prevRaw[:], raw)
	sibling := map[string]string{
		"id":         "fork",
		"parentId":   "evt-0",
		"payload":    "sibling",
		"prevDigest": events[0]["digest"],
		"digest":     audit.ComputeDigest("fork", "sibling", prevRaw),
	}
	rec := postAudit(t, map[string]any{"events": []any{events[1], sibling, events[0]}})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := decodeBody(t, rec)
	errs := body["errors"].([]any)
	if len(errs) != 1 {
		t.Fatalf("want single FORK, got %s", rec.Body.String())
	}
	only := errs[0].(map[string]any)
	if only["code"] != "FORK" || only["eventId"] != "evt-0" {
		t.Fatalf("want FORK anchored on parent evt-0, got %v", only)
	}
}

func TestPostAuditMissingParent(t *testing.T) {
	events := chainMaps(2)
	events[1]["parentId"] = "unknown-workstation"
	rec := postAudit(t, map[string]any{"events": events})
	body := decodeBody(t, rec)
	errs := body["errors"].([]any)
	for _, e := range errs {
		m := e.(map[string]any)
		if m["code"] == "MISSING_PARENT" && m["eventId"] == "evt-1" {
			return
		}
	}
	t.Fatalf("expected MISSING_PARENT evt-1, got %s", rec.Body.String())
}

func TestValidationErrors(t *testing.T) {
	zero := strings.Repeat("0", 64)
	cases := []struct {
		name string
		body string
	}{
		{"malformed json", `{not json`},
		{"empty events", `{"events":[]}`},
		{"too many events", tooManyBody()},
		{"missing field", `{"events":[{"id":"a","parentId":"","payload":"p","prevDigest":"` + zero + `"}]}`},
		{"bad digest length", `{"events":[{"id":"a","parentId":"","payload":"p","prevDigest":"00","digest":"` + zero + `"}]}`},
		{"uppercase digest", `{"events":[{"id":"a","parentId":"","payload":"p","prevDigest":"` + strings.Repeat("A", 64) + `","digest":"` + zero + `"}]}`},
		{"wrong type", `{"events":[{"id":1,"parentId":"","payload":"p","prevDigest":"` + zero + `","digest":"` + zero + `"}]}`},
		{"unknown field", `{"events":[{"id":"a","parentId":"","payload":"p","prevDigest":"` + zero + `","digest":"` + zero + `","x":1}]}`},
		{"duplicate ids", `{"events":[{"id":"a","parentId":"","payload":"p","prevDigest":"` + zero + `","digest":"` + zero + `"},{"id":"a","parentId":"a","payload":"q","prevDigest":"` + zero + `","digest":"` + zero + `"}]}`},
		{"empty id", `{"events":[{"id":"","parentId":"","payload":"p","prevDigest":"` + zero + `","digest":"` + zero + `"}]}`},
		{"null event", `{"events":[null]}`},
		{"trailing data", `{"events":[{"id":"a","parentId":"","payload":"p","prevDigest":"` + zero + `","digest":"` + zero + `"}]} junk`},
		{"invalid utf8", "{\"events\":[{\"id\":\"a\\xff\",\"parentId\":\"\",\"payload\":\"p\",\"prevDigest\":\"" + zero + "\",\"digest\":\"" + zero + "\"}]}"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := postAudit(t, tc.body)
			if rec.Code != http.StatusUnprocessableEntity {
				t.Fatalf("%s: status = %d, want 422, body=%s", tc.name, rec.Code, rec.Body.String())
			}
			body := decodeBody(t, rec)
			if body["code"] == nil || body["code"] == "" {
				t.Fatalf("%s: 422 must carry an error code, got %s", tc.name, rec.Body.String())
			}
		})
	}
}

func TestNonJSONContentTypeRejected(t *testing.T) {
	rdr := bytes.NewReader([]byte(`{"events":[]}`))
	req := httptest.NewRequest(http.MethodPost, "/audit", rdr)
	req.Header.Set("Content-Type", "text/plain")
	rec := httptest.NewRecorder()
	httpapi.NewMux().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d, want 415", rec.Code)
	}
}

func TestWrongMethod(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/audit", nil)
	rec := httptest.NewRecorder()
	httpapi.NewMux().ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /audit status = %d, want 405", rec.Code)
	}
}

func TestUnknownRoute(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/nope", nil)
	rec := httptest.NewRecorder()
	httpapi.NewMux().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestHealthz(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	httpapi.NewMux().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("healthz status = %d", rec.Code)
	}
}

func TestBoundary2000Accepted(t *testing.T) {
	rec := postAudit(t, map[string]any{"events": chainMaps(2000)})
	if rec.Code != http.StatusOK {
		t.Fatalf("2000 events should be accepted, got %d: %s", rec.Code, rec.Body.String())
	}
}

func tooManyBody() string {
	zero := strings.Repeat("0", 64)
	var b strings.Builder
	b.WriteString(`{"events":[`)
	for i := 0; i < 2001; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"id":"e%d","parentId":"","payload":"p","prevDigest":%q,"digest":%q}`, i, zero, zero)
	}
	b.WriteString(`]}`)
	return b.String()
}
