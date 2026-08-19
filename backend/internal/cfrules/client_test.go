package cfrules

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestEvaluateSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"expression_valid":true,"scheme_version":"cf-scheme-v1",
			"engine_version":"wirefilter-engine-0.6.1","fidelity_note":"expression only",
			"results":[{"ref":"e1","matched":true}]}`))
	}))
	defer srv.Close()

	c := New(srv.URL, time.Second)
	resp, err := c.Evaluate(context.Background(), `http.host eq "x"`, []CapturedRequest{{Ref: "e1"}})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if !resp.ExpressionValid || len(resp.Results) != 1 || !resp.Results[0].Matched {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if resp.FidelityNote == "" {
		t.Error("the fidelity limit must reach the caller (FR-073b)")
	}
}

// TestUnreachableSidecarDegradesRatherThanErrors is the point of the process
// boundary: CF rule testing becomes unavailable, and nothing else is affected.
func TestUnreachableSidecarDegradesRatherThanErrors(t *testing.T) {
	c := New("http://127.0.0.1:1", 200*time.Millisecond)
	resp, err := c.Evaluate(context.Background(), `http.host eq "x"`, nil)
	if err != nil {
		t.Fatalf("an unreachable sidecar must not surface as an error: %v", err)
	}
	if !resp.Unavailable {
		t.Fatal("the response must be marked unavailable")
	}
	if resp.Unreachable == "" {
		t.Error("the reason should be recorded for the operator")
	}
}

// TestUnavailableIsNotTheSameAsNoMatch: conflating them would let an operator
// read "we could not ask" as "the rule does not match".
func TestUnavailableIsNotTheSameAsNoMatch(t *testing.T) {
	c := New("http://127.0.0.1:1", 200*time.Millisecond)
	resp, _ := c.Evaluate(context.Background(), "x", nil)
	if len(resp.Results) != 0 {
		t.Fatal("an unavailable evaluation must produce no results at all, not a false one")
	}
}

func TestServerErrorIsUnavailableNotAResult(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	resp, err := New(srv.URL, time.Second).Evaluate(context.Background(), "x", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Unavailable {
		t.Error("a 5xx means we could not ask, not that nothing matched")
	}
}

// TestParseErrorIsDataNotAnError: the caller asked a well-formed question about
// a malformed expression, and the answer belongs in the UI.
func TestParseErrorIsData(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"expression_valid":false,"parse_error":"unknown field","results":[]}`))
	}))
	defer srv.Close()

	resp, err := New(srv.URL, time.Second).Evaluate(context.Background(), "bogus", nil)
	if err != nil {
		t.Fatalf("a parse error must not be a transport error: %v", err)
	}
	if resp.ExpressionValid || resp.ParseError == "" {
		t.Errorf("the parse error should be reported as data: %+v", resp)
	}
	if resp.Unavailable {
		t.Error("the sidecar answered; it is not unavailable")
	}
}

func TestNotConfigured(t *testing.T) {
	c := New("", time.Second)
	if c.Configured() {
		t.Fatal("an empty endpoint is not configured")
	}
	if _, err := c.Evaluate(context.Background(), "x", nil); err != ErrNotConfigured {
		t.Errorf("expected ErrNotConfigured, got %v", err)
	}
}

// TestFieldsOmitsAbsentValues: sending an empty value for a missing field would
// make it indistinguishable from a genuinely empty one, and the sidecar's caveat
// about absent fields is what signals uncertainty.
func TestFieldsOmitsAbsentValues(t *testing.T) {
	fields := FieldsFromFlow("GET", "shop.example.com", "/admin", "", "", "203.0.113.9")
	if _, present := fields["http.user_agent"]; present {
		t.Error("an absent user agent must be omitted, not sent as empty")
	}
	if _, present := fields["http.request.uri.query"]; present {
		t.Error("an absent query must be omitted")
	}
	if fields["http.request.uri"] != "/admin" {
		t.Errorf("uri should be assembled from path and query, got %v", fields["http.request.uri"])
	}

	withQuery := FieldsFromFlow("GET", "h", "/a", "b=1", "ua", "1.2.3.4")
	if withQuery["http.request.uri"] != "/a?b=1" {
		t.Errorf("uri should include the query, got %v", withQuery["http.request.uri"])
	}
}

func TestHealth(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer ok.Close()
	if err := New(ok.URL, time.Second).Health(context.Background()); err != nil {
		t.Errorf("healthy sidecar: %v", err)
	}

	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer bad.Close()
	if err := New(bad.URL, time.Second).Health(context.Background()); err == nil {
		t.Error("a non-200 health response must be an error")
	}

	if err := New("http://127.0.0.1:1", 200*time.Millisecond).Health(context.Background()); err == nil {
		t.Error("an unreachable sidecar must fail its health check")
	}
	if err := New("", time.Second).Health(context.Background()); err != ErrNotConfigured {
		t.Errorf("unconfigured: got %v", err)
	}
}

func TestMalformedResponseIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`not json`))
	}))
	defer srv.Close()
	if _, err := New(srv.URL, time.Second).Evaluate(context.Background(), "x", nil); err == nil {
		t.Error("an undecodable response must surface rather than be treated as no match")
	}
}

func TestCaveatsSurvive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"expression_valid":true,"results":[{"ref":"e1","matched":false,
			"caveats":["expression references http.user_agent, which the capture does not contain"]}]}`))
	}))
	defer srv.Close()

	resp, err := New(srv.URL, time.Second).Evaluate(context.Background(), "x", nil)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if len(resp.Results[0].Caveats) != 1 {
		t.Fatal("caveats must reach the caller; without them a false reads as safe")
	}
}

func TestTimeoutDefaults(t *testing.T) {
	if New("http://x", 0).Timeout != 10*time.Second {
		t.Error("a zero timeout must fall back to a bounded default, never to unbounded")
	}
}
