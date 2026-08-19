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

// TestRestartResumesInProgressFlows is the S7 scenario at the pipeline level:
// the processor dies mid-correlation, and the successor must RESUME the
// in-flight flows from persisted state rather than resetting — a restart that
// forgot its partial flows would close every one of them as spuriously partial
// and re-open duplicates for late records (FR-023).
//
// The durable-buffer half of S7 (JetStream redelivering unacked batches) is
// covered by the buffer's ack-after-process contract in internal/data/jetstream;
// this test covers the correlation-state half, which is the part a naive
// implementation loses.
func TestRestartResumesInProgressFlows(t *testing.T) {
	receivedAt := time.Date(2026, 8, 19, 12, 0, 5, 0, time.UTC)

	// --- First process lifetime: the Cloudflare record arrives, nginx has not.
	firstStore := &memStore{}
	firstWindow := window.New(window.Options{LateArrival: 15 * time.Minute, ExpectedLayers: 2})
	first := flow.NewPipeline(firstStore, &ingest.MemoryDeadLetter{}, firstWindow)
	first.Register(cloudflare.New())
	first.Now = func() time.Time { return receivedAt }

	if err := first.ProcessBatch(context.Background(), ingest.RawBatch{
		BatchID: "b1", Provider: schema.ProviderCloudflare, Tenant: "acme",
		ReceivedAt: receivedAt, Records: [][]byte{[]byte(cfRecord)},
	}); err != nil {
		t.Fatalf("first lifetime batch: %v", err)
	}
	first.Correlate()
	if _, err := first.Flush(context.Background()); err != nil {
		t.Fatalf("first flush: %v", err)
	}
	if len(firstStore.flows) != 0 {
		t.Fatal("the flow is still within its window and must not have closed")
	}

	// The process dies here. What survives is the window snapshot — in
	// production this is the Valkey-persisted correlation state.
	snapshot := firstWindow.Snapshot()
	if len(snapshot) != 1 {
		t.Fatalf("expected one in-flight flow in the snapshot, got %d", len(snapshot))
	}

	// --- Second process lifetime: restore, then the nginx record arrives.
	secondStore := &memStore{}
	secondWindow := window.New(window.Options{LateArrival: 15 * time.Minute, ExpectedLayers: 2})
	secondWindow.Restore(snapshot)
	second := flow.NewPipeline(secondStore, &ingest.MemoryDeadLetter{}, secondWindow)
	// A two-layer deployment: the window and the completeness verdict must agree.
	second.ExpectedLayers = []schema.Layer{schema.LayerEdge, schema.LayerOrigin}
	second.Register(nginx.New())
	second.Now = func() time.Time { return receivedAt.Add(time.Minute) }

	if err := second.ProcessBatch(context.Background(), ingest.RawBatch{
		BatchID: "b2", Provider: schema.ProviderNginx, Tenant: "acme",
		ReceivedAt: receivedAt.Add(time.Minute), Records: [][]byte{[]byte(ngxRecord)},
	}); err != nil {
		t.Fatalf("second lifetime batch: %v", err)
	}
	second.Correlate()
	if _, err := second.Flush(context.Background()); err != nil {
		t.Fatalf("second flush: %v", err)
	}

	// Both layers reported, so the flow closes COMPLETE — proof the restart
	// resumed rather than reset: a reset would have produced two partial flows.
	if len(secondStore.flows) != 1 {
		t.Fatalf("expected one flow after restart, got %d", len(secondStore.flows))
	}
	f := secondStore.flows[0]
	if f.Completeness != flow.Complete {
		t.Fatalf("the resumed flow gathered both layers and must be complete, got %q "+
			"(missing=%v) — a partial here means the restart lost the pre-crash state",
			f.Completeness, f.LayersMissing)
	}
	if len(f.Events) != 2 {
		t.Fatalf("expected the pre-crash event AND the post-restart event, got %d", len(f.Events))
	}
}

// TestRestartDoesNotDuplicateReplayedBatches covers the redelivery half:
// JetStream redelivers any batch that was processed but not yet acknowledged
// when the process died, so the successor will see some batches twice.
func TestRestartDoesNotDuplicateReplayedBatches(t *testing.T) {
	receivedAt := time.Date(2026, 8, 19, 12, 0, 5, 0, time.UTC)

	store := &memStore{}
	w := window.New(window.Options{LateArrival: 15 * time.Minute, ExpectedLayers: 2})
	p := flow.NewPipeline(store, &ingest.MemoryDeadLetter{}, w)
	p.ExpectedLayers = []schema.Layer{schema.LayerEdge, schema.LayerOrigin}
	p.Register(cloudflare.New())
	p.Register(nginx.New())
	p.Now = func() time.Time { return receivedAt }

	batchCF := ingest.RawBatch{
		BatchID: "replayed", Provider: schema.ProviderCloudflare, Tenant: "acme",
		ReceivedAt: receivedAt, Records: [][]byte{[]byte(cfRecord)},
	}
	// Delivered once before the crash, once after: at-least-once in action.
	for i := 0; i < 2; i++ {
		if err := p.ProcessBatch(context.Background(), batchCF); err != nil {
			t.Fatalf("delivery %d: %v", i, err)
		}
	}
	if err := p.ProcessBatch(context.Background(), ingest.RawBatch{
		BatchID: "ngx", Provider: schema.ProviderNginx, Tenant: "acme",
		ReceivedAt: receivedAt, Records: [][]byte{[]byte(ngxRecord)},
	}); err != nil {
		t.Fatalf("nginx: %v", err)
	}
	p.Correlate()
	p.Now = func() time.Time { return receivedAt.Add(time.Hour) }
	if _, err := p.Flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}

	if len(store.flows) != 1 || len(store.flows[0].Events) != 2 {
		t.Fatalf("a replayed batch must collapse to one occurrence: %d flows, %d events",
			len(store.flows), len(store.flows[0].Events))
	}
}
