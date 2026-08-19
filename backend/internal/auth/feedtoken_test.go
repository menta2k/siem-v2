package auth

import (
	"fmt"
	"strings"
	"testing"
)

// The feed token follows the invite token's design: id half for lookup,
// 256-bit random secret half stored only as a SHA-256 hash. Possession of the
// database therefore never yields a working ingest credential.
func TestFeedTokenRoundTrip(t *testing.T) {
	tok, err := NewFeedToken("feed-abc")
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	wire := tok.Encode()
	if !strings.HasPrefix(wire, "feed-abc.") {
		t.Fatalf("the wire form must lead with the feed id for O(1) lookup: %q", wire)
	}

	id, secret, err := SplitFeedToken(wire)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	if id != "feed-abc" {
		t.Errorf("id = %q", id)
	}
	if !FeedSecretMatches(secret, tok.SecretHash()) {
		t.Error("the presented secret must match its own stored hash")
	}
	if FeedSecretMatches(secret+"x", tok.SecretHash()) {
		t.Error("a perturbed secret must not match")
	}
}

func TestFeedTokensAreUnique(t *testing.T) {
	a, _ := NewFeedToken("f")
	b, _ := NewFeedToken("f")
	if a.Encode() == b.Encode() {
		t.Fatal("two mints must never coincide")
	}
}

func TestFeedTokenRefusesGarbage(t *testing.T) {
	for _, bad := range []string{"", "no-dot", ".leading", "trailing.", "a.b.c.d"} {
		if _, _, err := SplitFeedToken(bad); err == nil {
			t.Errorf("%q must not parse", bad)
		}
	}
}

// The token never renders through fmt — same REDACTED discipline as invites.
func TestFeedTokenRedactsItself(t *testing.T) {
	tok, _ := NewFeedToken("feed-abc")
	for _, rendered := range []string{
		fmt.Sprintf("%v", tok), fmt.Sprintf("%+v", tok), fmt.Sprintf("%#v", tok), fmt.Sprintf("%s", tok),
	} {
		if strings.Contains(rendered, tok.Encode()[len("feed-abc."):]) {
			t.Fatalf("secret leaked through fmt: %s", rendered)
		}
	}
}
