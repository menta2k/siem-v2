package auth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

var tnow = time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)

const testKey = "0123456789abcdef0123456789abcdef" // 32 bytes

func issuer(t *testing.T, rev RevocationStore) *TokenIssuer {
	t.Helper()
	ti, err := NewTokenIssuer(testKey, 10*time.Minute, 7*24*time.Hour, rev)
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	return ti.WithClock(func() time.Time { return tnow })
}

func ident() Identity {
	return Identity{PrincipalID: "acme-analyst", Email: "ana@acme.example.com",
		TenantID: "acme", Role: "analyst"}
}

type memRevocations struct {
	revoked map[string]bool
	err     error
}

func (m *memRevocations) Revoke(_ context.Context, id string, _ time.Duration) error {
	if m.revoked == nil {
		m.revoked = map[string]bool{}
	}
	m.revoked[id] = true
	return m.err
}
func (m *memRevocations) IsRevoked(_ context.Context, id string) (bool, error) {
	return m.revoked[id], m.err
}

func TestPairRoundTrip(t *testing.T) {
	ti := issuer(t, nil)
	pair, err := ti.IssuePair(ident())
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	claims, err := ti.ParseAccess(pair.AccessToken)
	if err != nil {
		t.Fatalf("parse access: %v", err)
	}
	if claims.TenantID != "acme" || claims.Subject != "acme-analyst" || claims.Role != "analyst" {
		t.Errorf("claims lost identity: %+v", claims)
	}
}

// TestPurposeConfusionRejected is the property the signed purpose exists for: a
// well-signed token of the wrong kind must fail everywhere except its own
// parser.
func TestPurposeConfusionRejected(t *testing.T) {
	ti := issuer(t, nil)
	pair, _ := ti.IssuePair(ident())
	challenge, _ := ti.IssueMFAChallenge(ident())

	if _, err := ti.ParseAccess(pair.RefreshToken); err == nil {
		t.Error("a refresh token must not pass as an access token")
	}
	if _, err := ti.ParseAccess(challenge); err == nil {
		t.Error("an mfa_pending token must not pass as an access token")
	}
	if _, err := ti.ParseRefresh(context.Background(), pair.AccessToken); err == nil {
		t.Error("an access token must not pass as a refresh token")
	}
	if _, err := ti.ParseMFAChallenge(pair.AccessToken); err == nil {
		t.Error("an access token must not pass as an MFA challenge")
	}
}

// TestRefreshExpiryIsItsOwn is the v1 cookie bug as a regression test: a cookie
// dated with the access expiry evicts itself within minutes.
func TestRefreshExpiryIsItsOwn(t *testing.T) {
	ti := issuer(t, nil)
	pair, _ := ti.IssuePair(ident())
	if !pair.RefreshExpiresAt.After(pair.ExpiresAt.Add(24 * time.Hour)) {
		t.Fatalf("refresh expiry (%v) must be far beyond access expiry (%v); "+
			"dating the cookie with the access expiry logs users out on reload",
			pair.RefreshExpiresAt, pair.ExpiresAt)
	}
}

func TestExpiredToken(t *testing.T) {
	ti := issuer(t, nil)
	pair, _ := ti.IssuePair(ident())

	late := ti.WithClock(func() time.Time { return tnow.Add(time.Hour) })
	if _, err := late.ParseAccess(pair.AccessToken); !errors.Is(err, ErrTokenExpired) {
		t.Errorf("want ErrTokenExpired, got %v", err)
	}
}

func TestRevocation(t *testing.T) {
	rev := &memRevocations{}
	ti := issuer(t, rev)
	pair, _ := ti.IssuePair(ident())

	if _, err := ti.ParseRefresh(context.Background(), pair.RefreshToken); err != nil {
		t.Fatalf("fresh refresh token must parse: %v", err)
	}
	if err := ti.Revoke(context.Background(), pair.RefreshToken); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := ti.ParseRefresh(context.Background(), pair.RefreshToken); !errors.Is(err, ErrTokenRevoked) {
		t.Errorf("a revoked token must be dead, got %v", err)
	}
}

// TestRevocationFailsClosed: serving a possibly-revoked token because the cache
// is down is the wrong direction to fail in.
func TestRevocationFailsClosed(t *testing.T) {
	rev := &memRevocations{err: errors.New("valkey down")}
	ti := issuer(t, rev)
	pair, _ := ti.IssuePair(ident())

	if _, err := ti.ParseRefresh(context.Background(), pair.RefreshToken); err == nil {
		t.Fatal("an uncheckable token must not be honoured")
	}
}

// TestAlgorithmConfusionRejected: a token claiming alg=none must never verify.
func TestAlgorithmConfusionRejected(t *testing.T) {
	ti := issuer(t, nil)
	// Hand-build an unsigned token: header {"alg":"none"}.
	unsigned := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0." +
		"eyJzdWIiOiJhY21lLWFuYWx5c3QiLCJ0ZW5hbnRfaWQiOiJhY21lIiwicHVycG9zZSI6ImFjY2VzcyIsImlzcyI6InNpZW0tdjIifQ."
	if _, err := ti.ParseAccess(unsigned); err == nil {
		t.Fatal("alg=none must be rejected")
	}
}

func TestWeakSigningKeyRejected(t *testing.T) {
	if _, err := NewTokenIssuer("short", time.Minute, time.Hour, nil); err == nil {
		t.Fatal("a signing key under 32 bytes must be refused at construction")
	}
}

func TestMFAChallengeIsShortLived(t *testing.T) {
	ti := issuer(t, nil)
	challenge, _ := ti.IssueMFAChallenge(ident())

	if _, err := ti.ParseMFAChallenge(challenge); err != nil {
		t.Fatalf("fresh challenge must parse: %v", err)
	}
	late := ti.WithClock(func() time.Time { return tnow.Add(6 * time.Minute) })
	if _, err := late.ParseMFAChallenge(challenge); !errors.Is(err, ErrTokenExpired) {
		t.Errorf("a challenge older than 5 minutes must be dead, got %v", err)
	}
}

func TestTamperedTokenRejected(t *testing.T) {
	ti := issuer(t, nil)
	pair, _ := ti.IssuePair(ident())
	tampered := strings.Replace(pair.AccessToken, ".", ".x", 1)
	if _, err := ti.ParseAccess(tampered); err == nil {
		t.Fatal("a tampered token must be rejected")
	}
}
