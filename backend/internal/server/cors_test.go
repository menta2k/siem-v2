package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func corsHandler(origins ...string) http.Handler {
	c := &CORS{AllowedOrigins: origins}
	return c.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
}

func TestAllowedOriginGetsHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/flows/search", nil)
	req.Header.Set("Origin", "http://localhost:3002")
	rec := httptest.NewRecorder()
	corsHandler("http://localhost:3002").ServeHTTP(rec, req)

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:3002" {
		t.Fatalf("expected the origin echoed back, got %q", got)
	}
	if rec.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Error("credentials must be permitted for the bearer identity to be sent")
	}
	if rec.Header().Get("Vary") != "Origin" {
		t.Error("Vary: Origin is required or a shared cache may serve one origin's response to another")
	}
}

// TestDisallowedOriginGetsNothing: the browser blocks the request, and we
// disclose nothing about what would have been allowed.
func TestDisallowedOriginGetsNothing(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/flows/search", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	rec := httptest.NewRecorder()
	corsHandler("http://localhost:3002").ServeHTTP(rec, req)

	if rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("a disallowed origin must receive no CORS grant")
	}
}

// TestNoWildcardEvenWhenEmpty guards against someone "fixing" CORS with a
// wildcard later: it cannot be combined with credentials and would expose
// tenant-scoped data to any site.
func TestNoWildcardEvenWhenEmpty(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/flows/search", nil)
	req.Header.Set("Origin", "https://anything.example.com")
	rec := httptest.NewRecorder()
	corsHandler().ServeHTTP(rec, req)

	if rec.Header().Get("Access-Control-Allow-Origin") == "*" {
		t.Fatal("a wildcard origin must never be issued by this API")
	}
}

func TestPreflightShortCircuits(t *testing.T) {
	var reached bool
	c := &CORS{AllowedOrigins: []string{"http://localhost:3002"}}
	h := c.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
	}))

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/flows/search", nil)
	req.Header.Set("Origin", "http://localhost:3002")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if reached {
		t.Error("a preflight must not reach the handler or it would run unauthenticated")
	}
	if rec.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", rec.Code)
	}
}

func TestSameOriginRequestUnaffected(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/flows/search", nil) // no Origin header
	rec := httptest.NewRecorder()
	corsHandler("http://localhost:3002").ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("a same-origin request must pass through, got %d", rec.Code)
	}
}
