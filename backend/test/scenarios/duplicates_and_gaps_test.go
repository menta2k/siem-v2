//go:build scenario

package scenarios

import (
	"context"
	"testing"
	"time"

	"github.com/menta2k/siem-v2/backend/internal/biz/flow"
	"github.com/menta2k/siem-v2/backend/internal/correlate/window"
	"github.com/menta2k/siem-v2/backend/internal/ingest"
	"github.com/menta2k/siem-v2/backend/internal/normalize/cloudflare"
	"github.com/menta2k/siem-v2/backend/internal/normalize/nginx"
	"github.com/menta2k/siem-v2/backend/internal/normalize/schema"
)

// memStore captures what the pipeline writes.
type memStore struct {
	flows []*flow.Flow
	raws  int
}

func (m *memStore) Store(_ context.Context, f *flow.Flow) error {
	m.flows = append(m.flows, f)
	return nil
}
func (m *memStore) StoreRaw(context.Context, string, schema.Provider, []flow.RawItem, time.Time) error {
	m.raws++
	return nil
}

func newScenarioPipeline(store *memStore) *flow.Pipeline {
	w := window.New(window.Options{LateArrival: 15 * time.Minute, ExpectedLayers: 4})
	p := flow.NewPipeline(store, &ingest.MemoryDeadLetter{}, w)
	p.Register(cloudflare.New())
	p.Register(nginx.New())
	p.Now = func() time.Time { return time.Date(2026, 8, 19, 12, 30, 0, 0, time.UTC) }
	return p
}

const cfRecord = `{"RayID":"dedup1234567890a","ParentRayID":"00","EdgeStartTimestamp":"2026-08-19T12:00:00.100Z","ClientIP":"203.0.113.9","ClientRequestHost":"shop.example.com","ClientRequestURI":"/x","ClientRequestMethod":"GET","EdgeResponseStatus":200,"SecurityAction":""}`
const ngxRecord = `{"time_iso8601":"2026-08-19T12:00:00+00:00","cf_ray":"dedup1234567890a-FRA","cf_connecting_ip":"203.0.113.9","host":"shop.example.com","request_method":"GET","request_uri":"/x","status":200,"body_bytes_sent":100,"request_time":0.05}`

// TestDuplicateDeliveryProducesOneOccurrence is the S2 scenario's first half:
// every provider here delivers at-least-once, so redelivery is routine and must
// collapse to a single occurrence in the flow (FR-007).
func TestDuplicateDeliveryProducesOneOccurrence(t *testing.T) {
	store := &memStore{}
	p := newScenarioPipeline(store)
	receivedAt := time.Date(2026, 8, 19, 12, 0, 5, 0, time.UTC)

	// The same two records, delivered three times each — a retried Logpush batch
	// and a Vector replay after a broken connection.
	for i := 0; i < 3; i++ {
		if err := p.ProcessBatch(context.Background(), ingest.RawBatch{
			BatchID: "cf-batch", Provider: schema.ProviderCloudflare, Tenant: "acme",
			ReceivedAt: receivedAt, Records: [][]byte{[]byte(cfRecord)},
		}); err != nil {
			t.Fatalf("cf batch %d: %v", i, err)
		}
		if err := p.ProcessBatch(context.Background(), ingest.RawBatch{
			BatchID: "ngx-batch", Provider: schema.ProviderNginx, Tenant: "acme",
			ReceivedAt: receivedAt, Records: [][]byte{[]byte(ngxRecord)},
		}); err != nil {
			t.Fatalf("ngx batch %d: %v", i, err)
		}
	}
	p.Correlate()
	p.Now = func() time.Time { return time.Date(2026, 8, 19, 13, 0, 0, 0, time.UTC) }
	if _, err := p.Flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}

	if len(store.flows) != 1 {
		t.Fatalf("three deliveries of one request must produce ONE flow, got %d", len(store.flows))
	}
	f := store.flows[0]
	if len(f.Events) != 2 {
		t.Fatalf("redelivery must not duplicate a layer: got %d events, want 2", len(f.Events))
	}
	seen := map[schema.Layer]int{}
	for _, e := range f.Events {
		seen[e.Layer]++
	}
	for layer, n := range seen {
		if n != 1 {
			t.Errorf("layer %s appears %d times; deduplication failed", layer, n)
		}
	}
}

// TestGapsCloseAsPartialWithTheAbsenceNamed is the second half: a request whose
// other providers never report must close as partial after the window, with
// each absent layer explicitly listed — "we never heard from the WAF" and "the
// WAF allowed it" must never look the same (FR-019).
func TestGapsCloseAsPartialWithTheAbsenceNamed(t *testing.T) {
	store := &memStore{}
	p := newScenarioPipeline(store)

	if err := p.ProcessBatch(context.Background(), ingest.RawBatch{
		BatchID: "cf-only", Provider: schema.ProviderCloudflare, Tenant: "acme",
		ReceivedAt: time.Date(2026, 8, 19, 12, 0, 5, 0, time.UTC),
		Records:    [][]byte{[]byte(cfRecord)},
	}); err != nil {
		t.Fatalf("batch: %v", err)
	}
	p.Correlate()

	// Within the window: nothing should close — the rest may still be arriving.
	if _, err := p.Flush(context.Background()); err != nil {
		t.Fatalf("early flush: %v", err)
	}
	if len(store.flows) != 0 {
		t.Fatal("a flow must not close as partial before its late-arrival window elapses")
	}

	// Past the window: it closes as partial, and the gaps are NAMED.
	p.Now = func() time.Time { return time.Date(2026, 8, 19, 13, 0, 0, 0, time.UTC) }
	if _, err := p.Flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if len(store.flows) != 1 {
		t.Fatalf("expected the lone flow to close, got %d", len(store.flows))
	}
	f := store.flows[0]
	if f.Completeness != flow.Partial {
		t.Fatalf("one layer of four is partial, got %q", f.Completeness)
	}
	missing := map[schema.Layer]bool{}
	for _, l := range f.LayersMissing {
		missing[l] = true
	}
	for _, want := range []schema.Layer{
		schema.LayerBotManagement, schema.LayerAppFirewall, schema.LayerOrigin,
	} {
		if !missing[want] {
			t.Errorf("absent layer %q must be listed explicitly, got %v", want, f.LayersMissing)
		}
	}
}
