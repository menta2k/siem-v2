package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// FeedToken is a per-feed ingest credential: `<feedID>.<secret>`.
//
// Same construction as the invite token, for the same reasons: the id half
// makes lookup O(1), the secret half carries 256 bits of fresh entropy, and
// only SHA-256 of the secret is ever stored — a stolen database yields no
// working credential. Unlike v1, which minted feed tokens in the browser and
// kept them reversibly sealed server-side, both mint and hash live here.
type FeedToken struct {
	feedID string
	secret string
}

// ErrInvalidFeedToken covers every unusable-token case indistinguishably.
var ErrInvalidFeedToken = errors.New("auth: invalid feed token")

// NewFeedToken mints a credential for one feed with a fresh random secret.
func NewFeedToken(feedID string) (FeedToken, error) {
	if feedID == "" || strings.Contains(feedID, ".") {
		return FeedToken{}, fmt.Errorf("auth: feed id must be non-empty and dot-free")
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return FeedToken{}, fmt.Errorf("generate feed secret: %w", err)
	}
	return FeedToken{
		feedID: feedID,
		secret: base64.RawURLEncoding.EncodeToString(buf),
	}, nil
}

// Encode returns the wire form. The ONLY deliberate way the secret leaves.
func (t FeedToken) Encode() string { return t.feedID + "." + t.secret }

// SecretHash is what the database stores.
func (t FeedToken) SecretHash() string {
	sum := sha256.Sum256([]byte(t.secret))
	return hex.EncodeToString(sum[:])
}

// String renders REDACTED under every fmt verb, so the careless path — a log
// line, an error message, a debug dump — never carries the credential.
func (t FeedToken) String() string { return "FeedToken(" + t.feedID + ".REDACTED)" }

// GoString keeps %#v as safe as %v.
func (t FeedToken) GoString() string { return t.String() }

// SplitFeedToken separates a presented wire token into id and secret.
func SplitFeedToken(wire string) (feedID, secret string, err error) {
	parts := strings.Split(wire, ".")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", ErrInvalidFeedToken
	}
	return parts[0], parts[1], nil
}

// FeedSecretMatches compares a presented secret against a stored hash in
// constant time over the digests.
func FeedSecretMatches(presented, storedHash string) bool {
	if storedHash == "" {
		return false // fail closed on an unset credential
	}
	sum := sha256.Sum256([]byte(presented))
	return subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(storedHash)) == 1
}
