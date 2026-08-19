// Package feedauth resolves per-feed ingest credentials for the receivers.
//
// The hot path never touches the database: an in-memory snapshot is refreshed
// on an interval, so a database blip degrades to slightly-stale credentials
// rather than refused deliveries (Constitution I: Ingest Never Blocks). The
// distinction between "bad credential" and "store never loaded" is kept
// explicit — the first is the sender's fault (401), the second is ours (503,
// so well-behaved senders back off and retry instead of dropping the batch).
package feedauth

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/menta2k/siem-v2/backend/internal/auth"
)

// Feed is the slice of feed state ingest needs.
type Feed struct {
	ID        string
	TenantID  string
	Provider  string
	Name      string
	TokenHash string
}

// Lister supplies the enabled feeds — implemented by the postgres FeedRepo.
type Lister interface {
	ListEnabled(ctx context.Context) ([]Feed, error)
}

// Store is the refreshed snapshot.
type Store struct {
	lister  Lister
	logger  *slog.Logger
	mu      sync.RWMutex
	byID    map[string]Feed
	loaded  atomic.Bool
	refresh time.Duration
}

// NewStore builds a store; call Run to start refreshing.
func NewStore(lister Lister, refresh time.Duration, logger *slog.Logger) *Store {
	if refresh <= 0 {
		refresh = 30 * time.Second
	}
	return &Store{lister: lister, logger: logger, refresh: refresh, byID: map[string]Feed{}}
}

// Run refreshes until the context ends. The first refresh is immediate.
func (s *Store) Run(ctx context.Context) {
	s.Refresh(ctx)
	t := time.NewTicker(s.refresh)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Refresh(ctx)
		}
	}
}

// Refresh loads the current enabled set. A failure keeps the previous
// snapshot: stale credentials beat refused deliveries.
func (s *Store) Refresh(ctx context.Context) {
	feeds, err := s.lister.ListEnabled(ctx)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("feed store refresh failed; serving previous snapshot", "error", err)
		}
		return
	}
	next := make(map[string]Feed, len(feeds))
	for _, f := range feeds {
		next[f.ID] = f
	}
	s.mu.Lock()
	s.byID = next
	s.mu.Unlock()
	s.loaded.Store(true)
}

// Loaded reports whether at least one refresh has succeeded. Before that,
// every check must be "unavailable", never "unauthorized".
func (s *Store) Loaded() bool { return s.loaded.Load() }

// Verdict is the tri-state outcome of a credential check.
type Verdict int

const (
	// Denied: the feed is unknown, disabled, provider-mismatched, or the
	// secret is wrong. All indistinguishable to the sender, by design.
	Denied Verdict = iota
	// Allowed: the credential verifies for this feed and provider.
	Allowed
	// Unavailable: the store has never loaded; the sender should retry.
	Unavailable
)

// Check authenticates one presented wire token against one URL position
// (provider + feed id from the path). The feed id appears in BOTH the path
// and the token; they must agree, so a leaked token cannot be replayed
// against a different feed's endpoint.
func (s *Store) Check(provider, pathFeedID, wireToken string) (Feed, Verdict) {
	if !s.Loaded() {
		return Feed{}, Unavailable
	}
	tokenFeedID, secret, err := auth.SplitFeedToken(wireToken)
	if err != nil || tokenFeedID != pathFeedID {
		return Feed{}, Denied
	}
	s.mu.RLock()
	f, ok := s.byID[pathFeedID]
	s.mu.RUnlock()
	if !ok || f.Provider != provider {
		return Feed{}, Denied
	}
	if !auth.FeedSecretMatches(secret, f.TokenHash) {
		return Feed{}, Denied
	}
	return f, Allowed
}
