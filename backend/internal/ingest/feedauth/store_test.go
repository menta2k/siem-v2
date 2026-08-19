package feedauth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/menta2k/siem-v2/backend/internal/auth"
)

type fakeLister struct {
	feeds []Feed
	err   error
}

func (f *fakeLister) ListEnabled(context.Context) ([]Feed, error) { return f.feeds, f.err }

func minted(t *testing.T, feedID string) (wire string, hash string) {
	t.Helper()
	tok, err := auth.NewFeedToken(feedID)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	return tok.Encode(), tok.SecretHash()
}

func TestCheckCoversTheWholeVerdictSpace(t *testing.T) {
	wire, hash := minted(t, "feed-1")
	otherWire, _ := minted(t, "feed-1") // same feed, different secret
	lister := &fakeLister{feeds: []Feed{
		{ID: "feed-1", TenantID: "acme", Provider: "nginx", TokenHash: hash},
	}}
	s := NewStore(lister, time.Minute, nil)

	if _, v := s.Check("nginx", "feed-1", wire); v != Unavailable {
		t.Fatal("before the first refresh every check must be Unavailable — ours, not the sender's, fault")
	}
	s.Refresh(context.Background())

	if f, v := s.Check("nginx", "feed-1", wire); v != Allowed || f.TenantID != "acme" {
		t.Errorf("the right token at the right path must be Allowed with the feed attached, got %v", v)
	}
	for name, tc := range map[string][3]string{
		"wrong secret":           {"nginx", "feed-1", otherWire},
		"provider mismatch":      {"cloudflare", "feed-1", wire},
		"path/token id mismatch": {"nginx", "feed-2", wire},
		"unknown feed":           {"nginx", "feed-9", "feed-9.xyz"},
		"garbage token":          {"nginx", "feed-1", "not-a-token"},
	} {
		if _, v := s.Check(tc[0], tc[1], tc[2]); v != Denied {
			t.Errorf("%s must be Denied, got %v", name, v)
		}
	}
}

func TestFailedRefreshKeepsServingThePreviousSnapshot(t *testing.T) {
	wire, hash := minted(t, "feed-1")
	lister := &fakeLister{feeds: []Feed{{ID: "feed-1", Provider: "nginx", TokenHash: hash}}}
	s := NewStore(lister, time.Minute, nil)
	s.Refresh(context.Background())

	lister.err = errors.New("db down")
	s.Refresh(context.Background())

	if _, v := s.Check("nginx", "feed-1", wire); v != Allowed {
		t.Error("a refresh failure must keep the last good snapshot serving")
	}
}

func TestDisabledFeedDisappearsOnRefresh(t *testing.T) {
	wire, hash := minted(t, "feed-1")
	lister := &fakeLister{feeds: []Feed{{ID: "feed-1", Provider: "nginx", TokenHash: hash}}}
	s := NewStore(lister, time.Minute, nil)
	s.Refresh(context.Background())

	lister.feeds = nil // operator disabled it; ListEnabled no longer returns it
	s.Refresh(context.Background())

	if _, v := s.Check("nginx", "feed-1", wire); v != Denied {
		t.Error("a disabled feed's token must stop working at the next refresh")
	}
}
