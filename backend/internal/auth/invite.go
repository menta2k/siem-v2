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
	"time"
)

// DefaultInviteTTL is how long a setup token stays redeemable.
//
// A week: long enough to survive a new joiner's first weekend, short enough
// that a token sitting in a forgotten chat message stops being a live
// credential. An expired invite is not a dead end — an admin re-issues one.
const DefaultInviteTTL = 7 * 24 * time.Hour

// MinPasswordLength is the floor for a password a user chooses for themselves.
//
// Length is the only rule. Composition rules ("one digit, one symbol")
// measurably push people toward Passw0rd! and away from the long passphrases
// that actually resist an offline attack on a stolen argon2id hash.
const MinPasswordLength = 12

// Invite token errors. All are coarse on purpose: a caller learns that a setup
// link is unusable, never which of the several reasons applies, so the endpoint
// cannot be used to probe for live tokens or existing accounts.
var (
	ErrInvalidInviteToken = errors.New("auth: invalid invite token")
	ErrWeakPassword       = fmt.Errorf(
		"auth: password must be at least %d characters", MinPasswordLength)
)

// inviteSecretBytes is the entropy of the secret half. 256 bits, which is what
// lets the stored hash be a plain SHA-256 rather than a memory-hard one.
const inviteSecretBytes = 32

// InviteToken is a one-time account setup credential.
//
// It is deliberately SELF-DESCRIBING: the encoded form carries the tenant and
// principal it belongs to alongside the secret. That is what lets redemption —
// which runs before any login and therefore has no tenant context — look the
// invite up by its primary key instead of scanning a hash column across every
// tenant's rows. The identifiers are not secret; they name the holder's own
// account, and possessing them grants nothing without the secret half.
//
// It renders REDACTED under every fmt verb (see String and GoString). Making
// the secret field unexported is not enough on its own — %v prints unexported
// fields too — and the wire form is therefore only ever produced by an explicit
// call to Encode.
//
// v2 divergence from v1: identifiers are strings, so the key half is the two
// ids NUL-joined and base64url-encoded rather than two packed UUIDs.
type InviteToken struct {
	TenantID    string
	PrincipalID string

	// secret is unexported so it cannot be read, logged, or serialised by
	// accident.
	secret string
}

// NewInviteToken mints a token for a principal, with a fresh random secret.
func NewInviteToken(tenantID, principalID string) (InviteToken, error) {
	if tenantID == "" || principalID == "" {
		return InviteToken{}, errors.New("auth: invite token needs a tenant and a principal")
	}
	if strings.ContainsRune(tenantID, 0) || strings.ContainsRune(principalID, 0) {
		return InviteToken{}, errors.New("auth: identifiers must not contain NUL")
	}

	buf := make([]byte, inviteSecretBytes)
	if _, err := rand.Read(buf); err != nil {
		return InviteToken{}, fmt.Errorf("generate invite secret: %w", err)
	}

	return InviteToken{
		TenantID:    tenantID,
		PrincipalID: principalID,
		secret:      base64.RawURLEncoding.EncodeToString(buf),
	}, nil
}

// String renders the token without its secret.
//
// This exists to be BORING on purpose. A setup token is a credential, and the
// default struct rendering prints unexported fields — so one
// `slog.Info("issued", "token", t)`, or one `%v` in a wrapped error, would put
// a live credential in the log aggregator forever. Implementing Stringer is
// what makes the careless path the safe one; the deliberate path is Encode.
func (t InviteToken) String() string {
	return fmt.Sprintf("InviteToken(tenant=%s principal=%s secret=REDACTED)", t.TenantID, t.PrincipalID)
}

// GoString covers %#v, which ignores String and would otherwise dump the raw
// struct.
func (t InviteToken) GoString() string { return t.String() }

// Encode returns the wire form handed to the invited user. The ONLY method that
// produces the secret, so every place a live token can escape is greppable.
func (t InviteToken) Encode() string {
	keys := t.TenantID + "\x00" + t.PrincipalID
	return base64.RawURLEncoding.EncodeToString([]byte(keys)) + "." + t.secret
}

// ParseInviteToken decodes a presented token. It proves nothing about validity:
// the secret still has to be checked against the stored hash, and the invite
// still has to be unspent and unexpired.
func ParseInviteToken(encoded string) (InviteToken, error) {
	keysPart, secret, found := strings.Cut(strings.TrimSpace(encoded), ".")
	if !found || keysPart == "" || secret == "" {
		return InviteToken{}, ErrInvalidInviteToken
	}

	keys, err := base64.RawURLEncoding.DecodeString(keysPart)
	if err != nil {
		return InviteToken{}, ErrInvalidInviteToken
	}
	tenantID, principalID, found := strings.Cut(string(keys), "\x00")
	if !found || tenantID == "" || principalID == "" {
		return InviteToken{}, ErrInvalidInviteToken
	}

	return InviteToken{TenantID: tenantID, PrincipalID: principalID, secret: secret}, nil
}

// SecretHash is what gets persisted. The token is unrecoverable from it.
func (t InviteToken) SecretHash() string {
	sum := sha256.Sum256([]byte(t.secret))
	return hex.EncodeToString(sum[:])
}

// MatchesHash reports whether this token's secret produced the stored hash.
//
// Constant-time. The secret is high-entropy enough that a timing side channel
// is not a realistic attack, but a credential comparison that leaks its prefix
// is the kind of thing that stays wrong once it is written down as correct.
func (t InviteToken) MatchesHash(storedHash string) bool {
	if storedHash == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(t.SecretHash()), []byte(storedHash)) == 1
}

// ValidatePassword enforces the floor for a self-chosen password.
func ValidatePassword(password string) error {
	if len([]rune(password)) < MinPasswordLength {
		return ErrWeakPassword
	}
	return nil
}
