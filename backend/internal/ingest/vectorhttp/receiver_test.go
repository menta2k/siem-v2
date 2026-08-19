package vectorhttp

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/menta2k/siem-v2/backend/internal/ingest"
	"github.com/menta2k/siem-v2/backend/internal/normalize/schema"
)

func newReceiver(buf ingest.Buffer) *Receiver {
	return &Receiver{
		Buffer: buf, Secret: "vec-token", Tenant: "acme", SourceID: "nginx-1",
		Provider: schema.ProviderNginx, MaxBodyBytes: 1 << 20,
		Now: func() time.Time { return time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC) },
	}
}

func post(t *testing.T, r *Receiver, body []byte, auth string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/ingest/v1/vector/nginx", bytes.NewReader(body))
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func TestBatchBuffered(t *testing.T) {
	buf := &ingest.MemoryBuffer{}
	body := []byte("line one\nline two\n\nline three\n")
	if resp := post(t, newReceiver(buf), body, "Bearer vec-token"); resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.Code)
	}
	if buf.RecordCount() != 3 {
		t.Errorf("expected 3 records with the blank line skipped, got %d", buf.RecordCount())
	}
	if buf.Batches[0].Provider != schema.ProviderNginx {
		t.Error("provider must come from the receiver configuration, not the payload")
	}
}

// TestBufferFailureReturns503 matters more here than it looks: Vector's
// end-to-end acknowledgements mean a 503 holds the events, while a 200 would let
// it advance its file cursor past data we never stored.
func TestBufferFailureReturns503(t *testing.T) {
	resp := post(t, newReceiver(failingBuffer{}), []byte("a line\n"), "Bearer vec-token")
	if resp.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 so Vector retains and retries, got %d", resp.Code)
	}
}

func TestUnauthorizedRejected(t *testing.T) {
	if resp := post(t, newReceiver(&ingest.MemoryBuffer{}), []byte("x\n"), "Bearer wrong"); resp.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.Code)
	}
	if resp := post(t, newReceiver(&ingest.MemoryBuffer{}), []byte("x\n"), ""); resp.Code != http.StatusUnauthorized {
		t.Fatalf("missing credential must be rejected, got %d", resp.Code)
	}
}

func TestEmptyBodyAccepted(t *testing.T) {
	if resp := post(t, newReceiver(&ingest.MemoryBuffer{}), []byte("\n\n"), "Bearer vec-token"); resp.Code != http.StatusOK {
		t.Fatalf("an empty delivery is legal, got %d", resp.Code)
	}
}

type failingBuffer struct{}

func (failingBuffer) Append(context.Context, ingest.RawBatch) error { return errors.New("down") }

func TestGzipBodyAccepted(t *testing.T) {
	buf := &ingest.MemoryBuffer{}
	var out bytes.Buffer
	gz := gzip.NewWriter(&out)
	gz.Write([]byte("line one\nline two\n"))
	gz.Close()

	req := httptest.NewRequest(http.MethodPost, "/ingest/v1/vector/nginx", bytes.NewReader(out.Bytes()))
	req.Header.Set("Authorization", "Bearer vec-token")
	req.Header.Set("Content-Encoding", "gzip")
	rec := httptest.NewRecorder()
	newReceiver(buf).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if buf.RecordCount() != 2 {
		t.Errorf("expected 2 records from the gzipped body, got %d", buf.RecordCount())
	}
}

func TestOversizedRejected(t *testing.T) {
	r := newReceiver(&ingest.MemoryBuffer{})
	r.MaxBodyBytes = 5
	if resp := post(t, r, []byte("much longer than five bytes"), "Bearer vec-token"); resp.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", resp.Code)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/ingest/v1/vector/nginx", nil)
	rec := httptest.NewRecorder()
	newReceiver(&ingest.MemoryBuffer{}).ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
}
