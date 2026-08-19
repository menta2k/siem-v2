package auth

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestInviteRoundTrip(t *testing.T) {
	tok, err := NewInviteToken("acme", "acme-newhire")
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	parsed, err := ParseInviteToken(tok.Encode())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.TenantID != "acme" || parsed.PrincipalID != "acme-newhire" {
		t.Errorf("identity lost in round trip: %+v", parsed)
	}
	if !parsed.MatchesHash(tok.SecretHash()) {
		t.Error("the round-tripped secret must match the stored hash")
	}
}

// TestSecretNeverLeaksThroughFormatting is the property the unexported field
// and Stringer exist for: one slog call or %v in a wrapped error must not put
// a live credential in the log aggregator.
func TestSecretNeverLeaksThroughFormatting(t *testing.T) {
	tok, _ := NewInviteToken("acme", "acme-newhire")
	secretPart := strings.SplitN(tok.Encode(), ".", 2)[1]

	for name, rendered := range map[string]string{
		"%v":      fmt.Sprintf("%v", tok),
		"%+v":     fmt.Sprintf("%+v", tok),
		"%#v":     fmt.Sprintf("%#v", tok),
		"%s":      fmt.Sprintf("%s", tok),
		"wrapped": fmt.Errorf("issue failed for %v", tok).Error(),
	} {
		if strings.Contains(rendered, secretPart) {
			t.Errorf("the secret leaked through %s: %s", name, rendered)
		}
		if !strings.Contains(rendered, "REDACTED") {
			t.Errorf("%s should render REDACTED, got %s", name, rendered)
		}
	}
}

func TestWrongSecretDoesNotMatch(t *testing.T) {
	a, _ := NewInviteToken("acme", "acme-newhire")
	b, _ := NewInviteToken("acme", "acme-newhire")
	if a.MatchesHash(b.SecretHash()) {
		t.Fatal("two invites for the same principal must have unrelated secrets")
	}
	if a.MatchesHash("") {
		t.Fatal("an empty stored hash must match nothing")
	}
}

// TestGarbageParsesToOneCoarseError: the endpoint must not be usable to probe
// which failure applies.
func TestGarbageParsesToOneCoarseError(t *testing.T) {
	for _, in := range []string{
		"", ".", "x.", ".x", "notbase64!.secret",
		"eA.secret",     // decodes to "x": no NUL separator
		"AA.secret",     // decodes to a NUL only: empty ids
		"one.two.three", // extra separator ends up in the secret half; parse succeeds structurally
	} {
		if _, err := ParseInviteToken(in); err != nil && !errors.Is(err, ErrInvalidInviteToken) {
			t.Errorf("%q: every failure must be ErrInvalidInviteToken, got %v", in, err)
		}
	}
}

func TestPasswordFloor(t *testing.T) {
	if err := ValidatePassword("short"); !errors.Is(err, ErrWeakPassword) {
		t.Error("a short password must be refused")
	}
	if err := ValidatePassword("a long enough passphrase"); err != nil {
		t.Errorf("length is the only rule: %v", err)
	}
	// Rune count, not byte count: a 12-character non-ASCII passphrase is valid.
	if err := ValidatePassword("паролафраза!"); err != nil {
		t.Errorf("length is counted in runes: %v", err)
	}
}

func TestInviteTTLIsBounded(t *testing.T) {
	if DefaultInviteTTL > 14*24*time.Hour {
		t.Error("an invite living beyond two weeks is a forgotten credential, not a convenience")
	}
}
