package ingest

import (
	"crypto/subtle"
	"fmt"
	"strings"
)

// MaxRecordBytes bounds a single record. Oversized records are truncated with
// the truncation recorded explicitly, never silently, because a downstream rule
// evaluation over a truncated body would otherwise produce a confident wrong
// answer (FR-035).
const MaxRecordBytes = 1 << 20 // 1 MiB

// ValidateBatchSize rejects a delivery larger than the configured ceiling before
// it is read into memory.
func ValidateBatchSize(contentLength, maxBytes int64) error {
	if maxBytes > 0 && contentLength > maxBytes {
		return fmt.Errorf("batch of %d bytes exceeds the %d byte limit", contentLength, maxBytes)
	}
	return nil
}

// AuthenticateSecret compares a presented credential against the expected one in
// constant time.
//
// Constant-time comparison matters here specifically because the ingest endpoint
// is internet-facing by necessity — Cloudflare must be able to reach it — and a
// timing oracle on the shared secret would be remotely exploitable.
func AuthenticateSecret(presented, expected string) bool {
	if expected == "" {
		// An unset secret must never authenticate. Failing open here would leave
		// a misconfigured deployment silently unauthenticated.
		return false
	}
	return subtle.ConstantTimeCompare([]byte(presented), []byte(expected)) == 1
}

// BearerToken extracts a token from an Authorization header value, accepting
// both "Bearer x" and a bare token.
func BearerToken(header string) string {
	h := strings.TrimSpace(header)
	if h == "" {
		return ""
	}
	const prefix = "bearer "
	if len(h) >= len(prefix) && strings.EqualFold(h[:len(prefix)], prefix) {
		return strings.TrimSpace(h[len(prefix):])
	}
	return h
}

// TruncateRecord bounds a single record, reporting whether it was cut.
func TruncateRecord(b []byte) (out []byte, truncated bool) {
	if len(b) <= MaxRecordBytes {
		return b, false
	}
	return b[:MaxRecordBytes], true
}
