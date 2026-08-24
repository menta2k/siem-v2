// Package rulenames resolves Cloudflare rule ids to human names, caching what it
// has looked up. Unlike v1 it needs no Cloudflare API token: the names are
// harvested from the ingested Logpush data (see victorialogs.RuleNamesFor).
//
// Names are DECORATION. Every method degrades to "no name" rather than to an
// error — a page that failed because a label was unavailable would be strictly
// worse than one showing the bare rule id, which is what it showed before.
package rulenames

import (
	"context"
	"sync"
	"time"
)

// Reader resolves rule ids to descriptions within one tenant.
type Reader interface {
	RuleNamesFor(ctx context.Context, tenant string, ruleIDs []string) (map[string]string, error)
}

// DefaultCacheTTL is how long a resolved name is reused. Short, because a rule
// RENAME should reach the console promptly, and the lookup is cheap.
const DefaultCacheTTL = 5 * time.Minute

// cacheKey scopes an entry to a tenant. The tenant is part of the KEY, not a
// filter applied afterwards: these are one customer's rule names held in a
// process shared by all of them, and a key on the id alone would serve tenant
// A's description to tenant B for any managed rule id they have in common.
type cacheKey struct {
	tenant string
	ruleID string
}

// Resolver names rules for the read paths, caching what it looked up.
type Resolver struct {
	reader Reader
	ttl    time.Duration
	now    func() time.Time

	mu     sync.RWMutex
	names  map[cacheKey]string
	loaded map[cacheKey]time.Time
}

// NewResolver constructs a resolver over the name reader. A nil reader yields a
// resolver whose Describe always returns nothing — the no-token, no-data case.
func NewResolver(reader Reader, ttl time.Duration) *Resolver {
	if ttl <= 0 {
		ttl = DefaultCacheTTL
	}
	return &Resolver{
		reader: reader,
		ttl:    ttl,
		now:    time.Now,
		names:  map[cacheKey]string{},
		loaded: map[cacheKey]time.Time{},
	}
}

// Describe resolves rule ids for one tenant, returning only those it could name.
func (r *Resolver) Describe(ctx context.Context, tenant string, ruleIDs []string) map[string]string {
	resolved := map[string]string{}
	if r == nil || r.reader == nil || tenant == "" || len(ruleIDs) == 0 {
		return resolved
	}

	missing := r.cached(tenant, ruleIDs, resolved)
	if len(missing) == 0 {
		return resolved
	}

	found, err := r.reader.RuleNamesFor(ctx, tenant, missing)
	if err != nil {
		return resolved
	}

	// A MISS IS CACHED TOO, as an empty name: a rule that never appears named
	// will never resolve, and without this every page view would re-ask for
	// exactly the ids that cannot be answered.
	at := r.now()
	r.mu.Lock()
	for _, id := range missing {
		key := cacheKey{tenant: tenant, ruleID: id}
		r.names[key] = found[id]
		r.loaded[key] = at
	}
	r.mu.Unlock()

	for id, name := range found {
		if name != "" {
			resolved[id] = name
		}
	}
	return resolved
}

// cached fills in what is already known and returns what must be fetched.
func (r *Resolver) cached(tenant string, ruleIDs []string, resolved map[string]string) []string {
	cutoff := r.now().Add(-r.ttl)

	r.mu.RLock()
	defer r.mu.RUnlock()

	var missing []string
	seen := map[cacheKey]struct{}{}
	for _, id := range ruleIDs {
		if id == "" {
			continue
		}
		key := cacheKey{tenant: tenant, ruleID: id}
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}

		at, known := r.loaded[key]
		if !known || at.Before(cutoff) {
			missing = append(missing, id)
			continue
		}
		if name := r.names[key]; name != "" {
			resolved[id] = name
		}
	}
	return missing
}
