package flow

import (
	"context"
	"testing"
	"time"

	"github.com/menta2k/siem-v2/backend/internal/correlate/window"
	"github.com/menta2k/siem-v2/backend/internal/ingest"
	"github.com/menta2k/siem-v2/backend/internal/ingest/filter"
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
type mergeStore struct {
	byID map[string]*Flow
	raw  []RawItem
}

func (c *mergeStore) Store(_ context.Context, f *Flow) error { c.byID[f.FlowID] = f; return nil }
func (c *mergeStore) StoreRaw(_ context.Context, _ string, _ schema.Provider, items []RawItem, _ time.Time) error {
	c.raw = append(c.raw, items...)
	return nil
}
func (c *mergeStore) Get(_ context.Context, _, flowID string) (*Flow, error) {
	return c.byID[flowID], nil
}

// TestFilteredRecordsAreNeverStoredAnywhere: a rule-matched record leaves no
// trace — no raw payload, no event, no flow. That irreversibility is the
// feature's contract and the reason everything around it fails open.
func TestFilteredRecordsAreNeverStoredAnywhere(t *testing.T) {
	store := &mergeStore{byID: map[string]*Flow{}}
	w := window.New(window.Options{LateArrival: 5 * time.Millisecond, ExpectedLayers: 1})
	p := NewPipeline(store, &ingest.MemoryDeadLetter{}, w)
	p.ExpectedLayers = []schema.Layer{schema.LayerOrigin}
	p.Register(nginx.New())

	set, err := filter.Compile([]filter.Rule{
		{Field: "request_path", Op: "prefix", Values: []string{"/nginx_status"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	p.Filters = func(string) *filter.Set { return set }

	line := func(path string) []byte {
		return []byte(`{"time_iso8601":"2026-08-20T09:00:00+03:00","cf_ray":"cafe000000000001-SOF","request_uri":"` + path + `","request_method":"GET","status":200,"host":"w.example.com","remote_addr":"1.2.3.4"}`)
	}
	if err := p.ProcessBatch(t.Context(), ingest.RawBatch{
		Provider: schema.ProviderNginx, Tenant: "acme", SourceID: "n1",
		Records: [][]byte{line("/nginx_status"), line("/kept")},
	}); err != nil {
		t.Fatalf("batch: %v", err)
	}
	if len(store.raw) != 1 {
		t.Fatalf("only the KEPT record's original may be stored, got %d raw items", len(store.raw))
	}
	p.Correlate()
	time.Sleep(10 * time.Millisecond)
	if _, err := p.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(store.byID) != 1 {
		t.Fatalf("exactly the kept record's flow must exist, got %d", len(store.byID))
	}
	for _, f := range store.byID {
		if f.Request.Path != "/kept" {
			t.Fatalf("the filtered path leaked into a flow: %q", f.Request.Path)
		}
	}
}

// TestSnapshotRestoreResumesOpenFlows: a restart mid-window must resume, not
// discard, a partial flow (FR-023) — the gap that lost a manually-triggered
// CF block during a deploy.
func TestSnapshotRestoreResumesOpenFlows(t *testing.T) {
	mk := func() *Pipeline {
		w := window.New(window.Options{LateArrival: time.Hour, ExpectedLayers: 4})
		p := NewPipeline(&mergeStore{byID: map[string]*Flow{}}, &ingest.MemoryDeadLetter{}, w)
		p.Register(cloudflare.New())
		return p
	}
	p1 := mk()
	cf := `{"RayID":"a2df4b3d4da6d0e8","ParentRayID":"00","EdgeStartTimestamp":"2026-08-20T06:20:45Z","ClientIP":"1.2.3.4","ClientRequestHost":"jobs.bg","ClientRequestURI":"/?a=x","ClientRequestMethod":"GET","EdgeResponseStatus":403,"SecurityAction":"block"}`
	if err := p1.ProcessBatch(t.Context(), ingest.RawBatch{
		Provider: schema.ProviderCloudflare, Tenant: "acme", SourceID: "c1",
		Records: [][]byte{[]byte(cf)},
	}); err != nil {
		t.Fatalf("batch: %v", err)
	}
	snap := p1.Snapshot() // drains events into the window and returns it
	if len(snap) != 1 {
		t.Fatalf("the open flow must be in the snapshot, got %d", len(snap))
	}

	// A fresh process restores and the flow is still in flight, still findable.
	p2 := mk()
	p2.Restore(snap)
	if p2.InFlight() != 1 {
		t.Fatalf("restored window must carry the open flow, in-flight=%d", p2.InFlight())
	}
}
