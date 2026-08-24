package rulenames

import (
	"context"
	"testing"
	"time"
)

// fakeReader counts calls and returns canned names per tenant.
type fakeReader struct {
	calls int
	names map[string]map[string]string // tenant -> id -> name
}

func (f *fakeReader) RuleNamesFor(_ context.Context, tenant string, ids []string) (map[string]string, error) {
	f.calls++
	out := map[string]string{}
	for _, id := range ids {
		if n := f.names[tenant][id]; n != "" {
			out[id] = n
		}
	}
	return out, nil
}

func TestResolvesAndCaches(t *testing.T) {
	fr := &fakeReader{names: map[string]map[string]string{
		"acme": {"r1": "Block SQLi", "r2": "Rate limit login"},
	}}
	r := NewResolver(fr, time.Minute)

	got := r.Describe(context.Background(), "acme", []string{"r1", "r2", "r1"})
	if got["r1"] != "Block SQLi" || got["r2"] != "Rate limit login" {
		t.Fatalf("unexpected names: %v", got)
	}
	// A second call for the same ids must not hit the reader again.
	_ = r.Describe(context.Background(), "acme", []string{"r1", "r2"})
	if fr.calls != 1 {
		t.Errorf("expected one reader call, got %d", fr.calls)
	}
}

func TestUnknownIdIsCachedAsAMiss(t *testing.T) {
	fr := &fakeReader{names: map[string]map[string]string{"acme": {}}}
	r := NewResolver(fr, time.Minute)

	if got := r.Describe(context.Background(), "acme", []string{"ghost"}); len(got) != 0 {
		t.Fatalf("an unknown id must resolve to nothing, got %v", got)
	}
	_ = r.Describe(context.Background(), "acme", []string{"ghost"})
	if fr.calls != 1 {
		t.Errorf("a miss must be cached, not re-asked; reader called %d times", fr.calls)
	}
}

func TestTenantScopedNames(t *testing.T) {
	fr := &fakeReader{names: map[string]map[string]string{
		"acme":   {"shared": "Acme name"},
		"globex": {"shared": "Globex name"},
	}}
	r := NewResolver(fr, time.Minute)

	if n := r.Describe(context.Background(), "acme", []string{"shared"})["shared"]; n != "Acme name" {
		t.Errorf("acme should see its own name, got %q", n)
	}
	if n := r.Describe(context.Background(), "globex", []string{"shared"})["shared"]; n != "Globex name" {
		t.Errorf("globex must not get acme's cached name for a shared id, got %q", n)
	}
}

func TestNilResolverAndEmptyTenantDegrade(t *testing.T) {
	var r *Resolver
	if got := r.Describe(context.Background(), "acme", []string{"r1"}); len(got) != 0 {
		t.Errorf("nil resolver must return nothing, got %v", got)
	}
	live := NewResolver(&fakeReader{}, time.Minute)
	if got := live.Describe(context.Background(), "", []string{"r1"}); len(got) != 0 {
		t.Errorf("empty tenant must resolve nothing, got %v", got)
	}
}
