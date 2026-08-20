package flow

import (
	"context"
	"testing"
	"time"

	"github.com/menta2k/siem-v2/backend/internal/correlate/window"
	"github.com/menta2k/siem-v2/backend/internal/ingest"
	"github.com/menta2k/siem-v2/backend/internal/normalize/cloudflare"
	"github.com/menta2k/siem-v2/backend/internal/normalize/nginx"
	"github.com/menta2k/siem-v2/backend/internal/normalize/schema"
)

// TestLateProviderAmendsTheStoredFlow: a Cloudflare record delivered by a
// batch cadence minutes after nginx's real-time record must MERGE into the
// already-stored flow, not open a second flow for the same request. This is
// the Amender finally wired into the pipeline — it existed, tested, unwired,
// while production showed cf-only flows beside nginx flows for the same ray.
func TestLateProviderAmendsTheStoredFlow(t *testing.T) {
	store := &mergeStore{byID: map[string]*Flow{}}
	w := window.New(window.Options{LateArrival: 10 * time.Millisecond, ExpectedLayers: 2})
	p := NewPipeline(store, &ingest.MemoryDeadLetter{}, w)
	p.ExpectedLayers = []schema.Layer{schema.LayerOrigin, schema.LayerEdge}
	p.Loader = store
	p.Register(nginx.New())
	p.Register(cloudflare.New())

	ray := "aaaabbbbcccc0001"
	ngLine := `{"time_iso8601":"2026-08-20T08:00:00+03:00","cf_ray":"` + ray + `-SOF","request_uri":"/x","request_method":"GET","status":200,"host":"w.example.com","remote_addr":"1.2.3.4"}`
	if err := p.ProcessBatch(t.Context(), ingest.RawBatch{
		Provider: schema.ProviderNginx, Tenant: "acme", SourceID: "n1",
		Records: [][]byte{[]byte(ngLine)},
	}); err != nil {
		t.Fatalf("nginx batch: %v", err)
	}
	p.Correlate()
	time.Sleep(20 * time.Millisecond)
	if _, err := p.Flush(t.Context()); err != nil {
		t.Fatalf("first flush: %v", err)
	}
	if len(store.byID) != 1 {
		t.Fatalf("expected the nginx flow stored, got %d", len(store.byID))
	}

	// Minutes later in wall-clock terms: the same ray arrives from Logpush.
	cfLine := `{"RayID":"` + ray + `","ParentRayID":"00","EdgeStartTimestamp":"2026-08-20T05:00:00Z","ClientIP":"5.6.7.8","ClientRequestHost":"w.example.com","ClientRequestURI":"/x","ClientRequestMethod":"GET","EdgeResponseStatus":200}`
	if err := p.ProcessBatch(t.Context(), ingest.RawBatch{
		Provider: schema.ProviderCloudflare, Tenant: "acme", SourceID: "c1",
		Records: [][]byte{[]byte(cfLine)},
	}); err != nil {
		t.Fatalf("cf batch: %v", err)
	}
	p.Correlate()
	time.Sleep(20 * time.Millisecond)
	if _, err := p.Flush(t.Context()); err != nil {
		t.Fatalf("second flush: %v", err)
	}

	if len(store.byID) != 1 {
		t.Fatalf("the late provider must AMEND, not open a second flow; flows stored: %d", len(store.byID))
	}
	var f *Flow
	for _, v := range store.byID {
		f = v
	}
	if len(f.Events) != 2 {
		t.Fatalf("merged flow must carry both providers' events, got %d", len(f.Events))
	}
	if !f.Amended {
		t.Fatal("a flow changed after it was stored must say so (FR-018)")
	}
}

// mergeStore is Store + FlowLoader over a map, keyed by flow id.
type mergeStore struct{ byID map[string]*Flow }

func (c *mergeStore) Store(_ context.Context, f *Flow) error { c.byID[f.FlowID] = f; return nil }
func (c *mergeStore) StoreRaw(context.Context, string, schema.Provider, []RawItem, time.Time) error {
	return nil
}
func (c *mergeStore) Get(_ context.Context, _, flowID string) (*Flow, error) {
	return c.byID[flowID], nil
}
