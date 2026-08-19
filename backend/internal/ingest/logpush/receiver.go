// Package logpush receives Cloudflare Logpush deliveries.
//
// Cloudflare dictates this contract; we conform to it. Three of its properties
// drive the whole implementation:
//
//   - At job creation Cloudflare POSTs a gzipped probe file. Fail it and the job
//     cannot be created at all.
//   - There is no HMAC or signature scheme. Authentication is a shared secret
//     that Cloudflare injects as a header via a `header_*` query parameter.
//   - Delivery is at-least-once, so duplicates are routine.
package logpush

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/menta2k/siem-v2/backend/internal/ingest"
	"github.com/menta2k/siem-v2/backend/internal/normalize/schema"
)

// validationProbe is the exact payload Cloudflare sends to validate a
// destination. It must be accepted with a 2xx and must NOT be ingested as log
// data — it is a handshake, not a record.
const validationProbe = `{"content":"tests"}`

// Clock is injected so tests are not at the mercy of wall-clock time.
type Clock func() time.Time

// Receiver handles Logpush deliveries for one feed.
type Receiver struct {
	Buffer  ingest.Buffer
	Deduper ingest.Deduper
	Secret  string
	// Authenticate, when set, replaces Secret as the credential check — the
	// per-feed token store plugs in here.
	Authenticate ingest.Authenticator
	Tenant       string
	SourceID     string
	MaxBodyBytes int64
	Now          Clock
	// OnValidation is called when the destination-validation probe is received,
	// so an operator can see that Cloudflare reached the endpoint.
	OnValidation func()
}

func (r *Receiver) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now().UTC()
}

// ServeHTTP implements the Logpush destination contract.
func (r *Receiver) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// PUT is accepted alongside POST because Cloudflare validates a Logpush
	// destination with a PUT; a 405 there blocks job creation (v1 lesson).
	if req.Method != http.MethodPost && req.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !r.authenticate(req) {
		// No detail: an unauthenticated caller learns nothing about why.
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if err := ingest.ValidateBatchSize(req.ContentLength, r.MaxBodyBytes); err != nil {
		http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
		return
	}

	body, err := readBody(req)
	if err != nil {
		// A body we cannot even decompress is malformed, not a transient failure.
		// Returning 4xx stops Cloudflare retrying something that will never work.
		http.Error(w, "malformed body", http.StatusBadRequest)
		return
	}

	// The validation probe must be answered 2xx but never stored.
	if isValidationProbe(body) {
		if r.OnValidation != nil {
			r.OnValidation()
		}
		w.WriteHeader(http.StatusOK)
		return
	}

	records, err := splitNDJSON(body)
	if err != nil {
		http.Error(w, "malformed body", http.StatusBadRequest)
		return
	}
	if len(records) == 0 {
		// An empty delivery is legal and means nothing to do.
		w.WriteHeader(http.StatusOK)
		return
	}

	receivedAt := r.now()
	batch := ingest.RawBatch{
		BatchID:    batchID(body),
		SourceID:   r.SourceID,
		Tenant:     r.Tenant,
		Provider:   schema.ProviderCloudflare,
		ReceivedAt: receivedAt,
		Records:    records,
	}

	// Durability BEFORE acknowledgement. Returning 200 first and buffering after
	// would lose the batch on a crash, and Cloudflare would never resend it
	// because a successful upload is not retried.
	if err := r.Buffer.Append(req.Context(), batch); err != nil {
		// 503 so Cloudflare retries. Never 200 on a buffer failure: that converts
		// a recoverable outage into permanent data loss.
		http.Error(w, "buffer unavailable", http.StatusServiceUnavailable)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (r *Receiver) authenticate(req *http.Request) bool {
	presented := ingest.BearerToken(req.Header.Get("Authorization"))
	if presented == "" {
		// Cloudflare injects headers via header_* query parameters, but some
		// configurations can only place the token in the query string itself.
		presented = req.URL.Query().Get("token")
	}
	return r.auth()(presented)
}

// auth prefers the pluggable Authenticate hook; absent one, the static Secret
// stands in, so existing wiring keeps its exact behaviour.
func (r *Receiver) auth() ingest.Authenticator {
	if r.Authenticate != nil {
		return r.Authenticate
	}
	return ingest.StaticSecret(r.Secret)
}

// readBody decompresses when needed.
//
// Whether live batches arrive gzipped is verification item V3 — only the
// validation probe's gzip is documented. Dispatching on the actual header rather
// than assuming either way means the receiver is correct under both answers.
func readBody(req *http.Request) ([]byte, error) {
	var reader io.Reader = req.Body

	encoding := strings.ToLower(strings.TrimSpace(req.Header.Get("Content-Encoding")))
	if encoding == "gzip" {
		gz, err := gzip.NewReader(req.Body)
		if err != nil {
			return nil, fmt.Errorf("gzip reader: %w", err)
		}
		defer gz.Close()
		reader = gz
	}

	body, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	// Some deliveries are gzipped without declaring it. Sniffing the magic bytes
	// costs nothing and avoids storing compressed bytes as if they were JSON.
	if encoding == "" && len(body) > 2 && body[0] == 0x1f && body[1] == 0x8b {
		gz, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("sniffed gzip: %w", err)
		}
		defer gz.Close()
		return io.ReadAll(gz)
	}
	return body, nil
}

// isValidationProbe recognizes the destination-validation payload.
func isValidationProbe(body []byte) bool {
	trimmed := strings.TrimSpace(string(body))
	return trimmed == validationProbe
}

// splitNDJSON separates the delivery into individual records, skipping blank
// lines. Oversized records are truncated with the fact recorded rather than
// silently dropped.
func splitNDJSON(body []byte) ([][]byte, error) {
	var records [][]byte
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 0, 64*1024), ingest.MaxRecordBytes+1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		rec, _ := ingest.TruncateRecord(line)
		cp := make([]byte, len(rec))
		copy(cp, rec)
		records = append(records, cp)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return records, nil
}

// batchID derives a deterministic id from the delivery's content, so that a
// redelivered batch is recognisable as the same batch.
func batchID(body []byte) string {
	sum := sha256.Sum256(body)
	return "cfb:" + hex.EncodeToString(sum[:12])
}

// Handler returns the receiver as an http.Handler.
func (r *Receiver) Handler() http.Handler { return r }

var _ = context.Background
