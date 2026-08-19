// Package vectorhttp receives deliveries from Vector for the nginx and F5 feeds.
//
// Unlike the Logpush path, this contract is ours, so it is kept deliberately
// plain: NDJSON in, 2xx only after durable buffering, 503 when the buffer is
// unavailable so Vector retains and retries rather than dropping.
package vectorhttp

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/menta2k/siem-v2/backend/internal/ingest"
	"github.com/menta2k/siem-v2/backend/internal/normalize/schema"
)

// Receiver handles one Vector-fed source.
type Receiver struct {
	Buffer ingest.Buffer
	Secret string
	// Authenticate, when set, replaces Secret as the credential check — the
	// per-feed token store plugs in here.
	Authenticate ingest.Authenticator
	Tenant       string
	SourceID     string
	Provider     schema.Provider
	MaxBodyBytes int64
	Now          func() time.Time
}

func (r *Receiver) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now().UTC()
}

func (r *Receiver) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !r.auth()(ingest.BearerToken(req.Header.Get("Authorization"))) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if err := ingest.ValidateBatchSize(req.ContentLength, r.MaxBodyBytes); err != nil {
		http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
		return
	}

	body, err := readBody(req)
	if err != nil {
		http.Error(w, "malformed body", http.StatusBadRequest)
		return
	}

	records := splitLines(body)
	if len(records) == 0 {
		w.WriteHeader(http.StatusOK)
		return
	}

	batch := ingest.RawBatch{
		BatchID:    "vec:" + contentHash(body),
		SourceID:   r.SourceID,
		Tenant:     r.Tenant,
		Provider:   r.Provider,
		ReceivedAt: r.now(),
		Records:    records,
	}

	if err := r.Buffer.Append(req.Context(), batch); err != nil {
		// Vector's end-to-end acknowledgements mean a 503 causes it to hold the
		// events and retry rather than advancing its source cursor. Returning 200
		// here would let it advance past data we never stored.
		http.Error(w, "buffer unavailable", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func readBody(req *http.Request) ([]byte, error) {
	var reader io.Reader = req.Body
	if strings.EqualFold(strings.TrimSpace(req.Header.Get("Content-Encoding")), "gzip") {
		gz, err := gzip.NewReader(req.Body)
		if err != nil {
			return nil, err
		}
		defer gz.Close()
		reader = gz
	}
	return io.ReadAll(reader)
}

func splitLines(body []byte) [][]byte {
	var out [][]byte
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
		out = append(out, cp)
	}
	return out
}

func contentHash(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:12])
}

func (r *Receiver) Handler() http.Handler { return r }

// auth prefers the pluggable Authenticate hook; absent one, the static Secret
// stands in, so existing wiring keeps its exact behaviour.
func (r *Receiver) auth() ingest.Authenticator {
	if r.Authenticate != nil {
		return r.Authenticate
	}
	return ingest.StaticSecret(r.Secret)
}
