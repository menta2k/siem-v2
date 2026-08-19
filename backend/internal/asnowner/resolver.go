package asnowner

import (
	"context"
	"sync"
	"time"
)

// Names is the lookup the resolver caches — implemented by the postgres repo.
type Names interface {
	NamesFor(ctx context.Context, asns []int) (map[int]string, error)
}

// DefaultCacheTTL bounds staleness. Attribution changes on registry timescales,
// so an hour of cache costs nothing and spares the database a query per page.
const DefaultCacheTTL = time.Hour

// Resolver batch-resolves ASN owner names with an in-process cache.
//
// Misses are cached as empty names deliberately (v1 behaviour): an ASN the
// table does not know would otherwise be re-queried on every single page load,
// and "unknown" is just as cacheable an answer as a name.
type Resolver struct {
	Source Names
	TTL    time.Duration
	Now    func() time.Time

	mu     sync.RWMutex
	names  map[int]string
	loaded map[int]time.Time
}

func (r *Resolver) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *Resolver) ttl() time.Duration {
	if r.TTL > 0 {
		return r.TTL
	}
	return DefaultCacheTTL
}

// Resolve returns owner names for the given ASNs; absent entries mean unknown.
// A lookup error returns whatever the cache already holds — decoration
// degrades, pages do not fail.
func (r *Resolver) Resolve(ctx context.Context, asns []int) map[int]string {
	out := make(map[int]string, len(asns))
	var missing []int
	now := r.now()

	r.mu.RLock()
	seen := map[int]bool{}
	for _, asn := range asns {
		if asn <= 0 || seen[asn] {
			continue
		}
		seen[asn] = true
		if at, ok := r.loaded[asn]; ok && now.Sub(at) < r.ttl() {
			if name := r.names[asn]; name != "" {
				out[asn] = name
			}
			continue
		}
		missing = append(missing, asn)
	}
	r.mu.RUnlock()

	if len(missing) == 0 || r.Source == nil {
		return out
	}
	fresh, err := r.Source.NamesFor(ctx, missing)
	if err != nil {
		return out
	}
	r.mu.Lock()
	if r.names == nil {
		r.names = map[int]string{}
		r.loaded = map[int]time.Time{}
	}
	for _, asn := range missing {
		name := fresh[asn] // empty for unknown — cached all the same
		r.names[asn] = name
		r.loaded[asn] = now
		if name != "" {
			out[asn] = name
		}
	}
	r.mu.Unlock()
	return out
}
