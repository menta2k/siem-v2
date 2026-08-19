package asnowner

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakeNames struct {
	table map[int]string
	calls int
	err   error
}

func (f *fakeNames) NamesFor(_ context.Context, asns []int) (map[int]string, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	out := map[int]string{}
	for _, a := range asns {
		if n, ok := f.table[a]; ok {
			out[a] = n
		}
	}
	return out, nil
}

func TestResolverCachesHitsAndMisses(t *testing.T) {
	src := &fakeNames{table: map[int]string{13335: "CLOUDFLARENET"}}
	r := &Resolver{Source: src}

	got := r.Resolve(context.Background(), []int{13335, 64512})
	if got[13335] != "CLOUDFLARENET" {
		t.Fatalf("resolve: %v", got)
	}
	if _, ok := got[64512]; ok {
		t.Fatal("unknown ASN must be absent, not empty-named")
	}
	// Second call: BOTH the hit and the miss must come from cache.
	r.Resolve(context.Background(), []int{13335, 64512})
	if src.calls != 1 {
		t.Fatalf("misses must be cached too — a page full of unknown ASNs would otherwise query every load; calls=%d", src.calls)
	}
}

func TestResolverExpiresByTTL(t *testing.T) {
	src := &fakeNames{table: map[int]string{3215: "Orange"}}
	clock := time.Now()
	r := &Resolver{Source: src, TTL: time.Hour, Now: func() time.Time { return clock }}
	r.Resolve(context.Background(), []int{3215})
	clock = clock.Add(2 * time.Hour)
	r.Resolve(context.Background(), []int{3215})
	if src.calls != 2 {
		t.Fatalf("an expired entry must re-query, calls=%d", src.calls)
	}
}

func TestResolverDegradesOnLookupError(t *testing.T) {
	src := &fakeNames{table: map[int]string{13335: "CLOUDFLARENET"}}
	r := &Resolver{Source: src}
	r.Resolve(context.Background(), []int{13335}) // warm the cache
	src.err = errors.New("db down")
	got := r.Resolve(context.Background(), []int{13335, 9999})
	if got[13335] != "CLOUDFLARENET" {
		t.Fatal("cached names must survive a lookup failure — decoration degrades, pages do not fail")
	}
}
