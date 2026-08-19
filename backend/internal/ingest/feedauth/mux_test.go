package feedauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/menta2k/siem-v2/backend/internal/ingest"
)

func newHandler(t *testing.T) (*Handler, *ingest.MemoryBuffer, string) {
	t.Helper()
	wire, hash := minted(t, "feed-ngx")
	lister := &fakeLister{feeds: []Feed{
		{ID: "feed-ngx", TenantID: "acme", Provider: "nginx", TokenHash: hash},
	}}
	store := NewStore(lister, time.Minute, nil)
	store.Refresh(context.Background())
	buf := &ingest.MemoryBuffer{}
	return &Handler{Store: store, Buffer: buf, MaxBodyBytes: 1 << 20}, buf, wire
}

func serve(h *Handler, method, path, token, body string) *httptest.ResponseRecorder {
	mux := http.NewServeMux()
	h.Mount(mux)
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestFeedDeliveryEndToEnd(t *testing.T) {
	h, buf, wire := newHandler(t)

	rec := serve(h, http.MethodPost, "/ingest/v1/nginx/feed-ngx", wire, `{"a":1}`+"\n")
	if rec.Code != http.StatusOK && rec.Code != http.StatusAccepted {
		t.Fatalf("authenticated delivery refused: %d %s", rec.Code, rec.Body.String())
	}
	if len(buf.Batches) != 1 {
		t.Fatalf("expected 1 buffered batch, got %d", len(buf.Batches))
	}
	b := buf.Batches[0]
	if b.SourceID != "feed-ngx" || b.Tenant != "acme" {
		t.Errorf("the batch must carry the FEED's identity, got source=%q tenant=%q", b.SourceID, b.Tenant)
	}
}

func TestFeedAuthFailures(t *testing.T) {
	h, buf, wire := newHandler(t)

	for name, tc := range map[string]struct {
		path, token string
	}{
		"wrong token":       {"/ingest/v1/nginx/feed-ngx", "feed-ngx.wrong"},
		"no token":          {"/ingest/v1/nginx/feed-ngx", ""},
		"provider mismatch": {"/ingest/v1/cloudflare/feed-ngx", wire},
		"other feed's path": {"/ingest/v1/nginx/feed-other", wire},
	} {
		if rec := serve(h, http.MethodPost, tc.path, tc.token, "x\n"); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: want 401, got %d", name, rec.Code)
		}
	}
	if len(buf.Batches) != 0 {
		t.Fatalf("nothing may reach the buffer unauthenticated, got %d batches", len(buf.Batches))
	}
}

func TestQueryTokenFallback(t *testing.T) {
	h, _, wire := newHandler(t)
	mux := http.NewServeMux()
	h.Mount(mux)
	req := httptest.NewRequest(http.MethodPost, "/ingest/v1/nginx/feed-ngx?token="+wire, strings.NewReader("x\n"))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK && rec.Code != http.StatusAccepted {
		t.Fatalf("query-token fallback must work for header-less senders: %d", rec.Code)
	}
}

func TestUnloadedStoreAnswers503(t *testing.T) {
	wire, hash := minted(t, "feed-ngx")
	lister := &fakeLister{feeds: []Feed{{ID: "feed-ngx", Provider: "nginx", TokenHash: hash}}}
	h := &Handler{Store: NewStore(lister, time.Minute, nil), Buffer: &ingest.MemoryBuffer{}}
	if rec := serve(h, http.MethodPost, "/ingest/v1/nginx/feed-ngx", wire, "x\n"); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("a never-loaded store is OUR outage: want 503 so senders retry, got %d", rec.Code)
	}
}
