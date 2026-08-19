package logpush

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/menta2k/siem-v2/backend/internal/ingest"
)

var fixedNow = time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)

func newReceiver(buf ingest.Buffer) *Receiver {
	return &Receiver{
		Buffer: buf, Secret: "s3cret-token", Tenant: "acme",
		SourceID: "cf-feed-1", MaxBodyBytes: 1 << 20,
		Now: func() time.Time { return fixedNow },
	}
}

func post(t *testing.T, r *Receiver, body []byte, opts ...func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/ingest/v1/cloudflare/logpush", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer s3cret-token")
	for _, o := range opts {
		o(req)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

// TestValidationProbeAccepted covers the handshake that gates job creation. Fail
// this and no Logpush job can be created at all.
func TestValidationProbeAccepted(t *testing.T) {
	buf := &ingest.MemoryBuffer{}
	var sawValidation bool
	r := newReceiver(buf)
	r.OnValidation = func() { sawValidation = true }

	resp := post(t, r, []byte(`{"content":"tests"}`))
	if resp.Code != http.StatusOK {
		t.Fatalf("the validation probe must be accepted, got %d", resp.Code)
	}
	if !sawValidation {
		t.Error("validation should be observable so an operator can confirm Cloudflare reached us")
	}
	if len(buf.Batches) != 0 {
		t.Error("the probe is a handshake, not a record; it must not be ingested as log data")
	}
}

func TestGzippedValidationProbeAccepted(t *testing.T) {
	buf := &ingest.MemoryBuffer{}
	body := gzipBytes(t, []byte(`{"content":"tests"}`))
	resp := post(t, newReceiver(buf), body, func(req *http.Request) {
		req.Header.Set("Content-Encoding", "gzip")
	})
	if resp.Code != http.StatusOK {
		t.Fatalf("the probe arrives gzipped and must be accepted, got %d", resp.Code)
	}
	if len(buf.Batches) != 0 {
		t.Error("probe must not be stored")
	}
}

func TestNDJSONBatchIsBuffered(t *testing.T) {
	buf := &ingest.MemoryBuffer{}
	body := []byte("{\"RayID\":\"a\"}\n{\"RayID\":\"b\"}\n\n{\"RayID\":\"c\"}\n")

	if resp := post(t, newReceiver(buf), body); resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.Code)
	}
	if len(buf.Batches) != 1 {
		t.Fatalf("expected one batch, got %d", len(buf.Batches))
	}
	if got := buf.RecordCount(); got != 3 {
		t.Errorf("blank lines should be skipped, expected 3 records, got %d", got)
	}
	if buf.Batches[0].Tenant != "acme" {
		t.Error("tenant must be stamped server-side from the feed configuration")
	}
}

// TestGzipSniffedWithoutHeader covers V3: whether live batches declare gzip is
// undocumented, so the receiver must be correct either way.
func TestGzipSniffedWithoutHeader(t *testing.T) {
	buf := &ingest.MemoryBuffer{}
	body := gzipBytes(t, []byte("{\"RayID\":\"a\"}\n{\"RayID\":\"b\"}\n"))

	// Deliberately NOT setting Content-Encoding.
	if resp := post(t, newReceiver(buf), body); resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.Code)
	}
	if got := buf.RecordCount(); got != 2 {
		t.Fatalf("gzip must be detected from the magic bytes, got %d records", got)
	}
	if bytes.Contains(buf.Batches[0].Records[0], []byte{0x1f, 0x8b}) {
		t.Error("compressed bytes were stored as if they were JSON")
	}
}

// TestBufferFailureReturns503 is the durability contract: never acknowledge a
// delivery we did not persist.
func TestBufferFailureReturns503(t *testing.T) {
	resp := post(t, newReceiver(failingBuffer{}), []byte("{\"RayID\":\"a\"}\n"))
	if resp.Code != http.StatusServiceUnavailable {
		t.Fatalf("a buffer failure must return 503 so Cloudflare retries, got %d", resp.Code)
	}
	if resp.Code == http.StatusOK {
		t.Fatal("acknowledging an unbuffered batch converts a recoverable outage into permanent loss")
	}
}

func TestAuthentication(t *testing.T) {
	buf := &ingest.MemoryBuffer{}
	r := newReceiver(buf)

	tests := []struct {
		name   string
		set    func(*http.Request)
		expect int
	}{
		{"valid bearer", func(req *http.Request) { req.Header.Set("Authorization", "Bearer s3cret-token") }, http.StatusOK},
		{"bare token", func(req *http.Request) { req.Header.Set("Authorization", "s3cret-token") }, http.StatusOK},
		{"query token fallback", func(req *http.Request) {
			req.Header.Del("Authorization")
			q := req.URL.Query()
			q.Set("token", "s3cret-token")
			req.URL.RawQuery = q.Encode()
		}, http.StatusOK},
		{"wrong secret", func(req *http.Request) { req.Header.Set("Authorization", "Bearer wrong") }, http.StatusUnauthorized},
		{"no credential", func(req *http.Request) { req.Header.Del("Authorization") }, http.StatusUnauthorized},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := post(t, r, []byte("{\"RayID\":\"a\"}\n"), tt.set)
			if resp.Code != tt.expect {
				t.Errorf("want %d, got %d", tt.expect, resp.Code)
			}
		})
	}
}

// TestEmptySecretNeverAuthenticates: a misconfigured deployment must fail closed.
func TestEmptySecretNeverAuthenticates(t *testing.T) {
	r := newReceiver(&ingest.MemoryBuffer{})
	r.Secret = ""
	resp := post(t, r, []byte("{}"), func(req *http.Request) {
		req.Header.Set("Authorization", "Bearer anything")
	})
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("an unset secret must never authenticate, got %d", resp.Code)
	}
}

func TestUnauthorizedResponseDisclosesNothing(t *testing.T) {
	resp := post(t, newReceiver(&ingest.MemoryBuffer{}), []byte("{}"), func(req *http.Request) {
		req.Header.Set("Authorization", "Bearer wrong")
	})
	body := strings.ToLower(resp.Body.String())
	for _, leak := range []string{"s3cret", "acme", "cf-feed", "expected"} {
		if strings.Contains(body, leak) {
			t.Errorf("unauthorized response leaked %q: %s", leak, resp.Body.String())
		}
	}
}

func TestOversizedBatchRejected(t *testing.T) {
	r := newReceiver(&ingest.MemoryBuffer{})
	r.MaxBodyBytes = 10
	resp := post(t, r, []byte(strings.Repeat("x", 100)))
	if resp.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", resp.Code)
	}
}

func TestMalformedGzipRejectedAsBadRequest(t *testing.T) {
	resp := post(t, newReceiver(&ingest.MemoryBuffer{}), []byte("not actually gzip"), func(req *http.Request) {
		req.Header.Set("Content-Encoding", "gzip")
	})
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("undecompressable body is permanently malformed; 4xx stops pointless retries, got %d", resp.Code)
	}
}

func TestBatchIDIsDeterministic(t *testing.T) {
	buf := &ingest.MemoryBuffer{}
	body := []byte("{\"RayID\":\"a\"}\n")
	post(t, newReceiver(buf), body)
	post(t, newReceiver(buf), body)

	if len(buf.Batches) != 2 {
		t.Fatalf("expected two appends, got %d", len(buf.Batches))
	}
	if buf.Batches[0].BatchID != buf.Batches[1].BatchID {
		t.Error("redelivery of identical content must yield the same batch id so it can be recognised")
	}
}

func TestGETRejected(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/ingest/v1/cloudflare/logpush", nil)
	rec := httptest.NewRecorder()
	newReceiver(&ingest.MemoryBuffer{}).ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
}

type failingBuffer struct{}

func (failingBuffer) Append(context.Context, ingest.RawBatch) error {
	return errors.New("jetstream unavailable")
}

func gzipBytes(t *testing.T, b []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	gz := gzip.NewWriter(&out)
	if _, err := gz.Write(b); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return out.Bytes()
}

// TestPUTAccepted pins the v1 lesson: Cloudflare validates a Logpush
// destination with a PUT, and a 405 there blocks job creation entirely.
func TestPUTAccepted(t *testing.T) {
	req := httptest.NewRequest(http.MethodPut, "/ingest/v1/cloudflare/logpush",
		strings.NewReader(`{"content":"tests"}`))
	req.Header.Set("Authorization", "Bearer s3cret-token")
	rec := httptest.NewRecorder()
	newReceiver(&ingest.MemoryBuffer{}).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("a destination-validation PUT must succeed, got %d: %s", rec.Code, rec.Body.String())
	}
}
