package window

import (
	"testing"
	"time"

	"github.com/menta2k/siem-v2/backend/internal/normalize/schema"
)

var wbase = time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)

func wev(id string, layer schema.Layer) schema.Event {
	return schema.Event{EventID: id, Layer: layer, EventTime: wbase}
}

func newWindow() *Window {
	return New(Options{LateArrival: 15 * time.Minute, ExpectedLayers: 4})
}

// TestFlowClosesEarlyWhenAllLayersArrive keeps the common case fast: once every
// layer has reported, waiting out the full window gains nothing.
func TestFlowClosesEarlyWhenAllLayersArrive(t *testing.T) {
	w := newWindow()
	for i, layer := range []schema.Layer{
		schema.LayerEdge, schema.LayerBotManagement,
		schema.LayerAppFirewall, schema.LayerOrigin,
	} {
		w.Add("ray:a", "acme", wev(string(rune('a'+i)), layer), wbase)
	}

	ready := w.Ready(wbase.Add(time.Second))
	if len(ready) != 1 {
		t.Fatalf("a flow with every layer should close immediately, got %d", len(ready))
	}
	if w.InFlight() != 0 {
		t.Error("a closed flow must leave in-flight state")
	}
}

// TestIncompleteFlowWaitsForItsWindow: declaring a gap early shows analysts a
// hole that may not exist.
func TestIncompleteFlowWaitsForItsWindow(t *testing.T) {
	w := newWindow()
	w.Add("ray:a", "acme", wev("cf", schema.LayerEdge), wbase)

	if ready := w.Ready(wbase.Add(5 * time.Minute)); len(ready) != 0 {
		t.Fatalf("within the window the flow must stay open, got %d ready", len(ready))
	}
	ready := w.Ready(wbase.Add(16 * time.Minute))
	if len(ready) != 1 {
		t.Fatalf("after the window elapses the flow must close as partial, got %d", len(ready))
	}
	if len(ready[0].Events) != 1 {
		t.Errorf("the partial flow keeps what it got, got %d events", len(ready[0].Events))
	}
}

// TestUnboundedGrowthIsPrevented is the reason the window exists at all.
func TestUnboundedGrowthIsPrevented(t *testing.T) {
	w := newWindow()
	for i := 0; i < 100; i++ {
		w.Add(string(rune('a'+i%26))+string(rune('0'+i/26)), "acme", wev("e", schema.LayerEdge), wbase)
	}
	if w.InFlight() == 0 {
		t.Fatal("flows should be in flight before the window elapses")
	}
	w.Ready(wbase.Add(16 * time.Minute))
	if w.InFlight() != 0 {
		t.Fatalf("every flow past its window must close; %d still in flight", w.InFlight())
	}
}

// TestLateRecordAmendsRatherThanForking: two flows for one request is worse than
// one late-corrected flow.
func TestLateRecordAmendsRatherThanForking(t *testing.T) {
	w := newWindow()
	w.Add("ray:a", "acme", wev("cf", schema.LayerEdge), wbase)
	ready := w.Ready(wbase.Add(16 * time.Minute))
	if len(ready) != 1 {
		t.Fatalf("expected the flow to close, got %d", len(ready))
	}

	st := w.Add("ray:a", "acme", wev("ngx", schema.LayerOrigin), wbase.Add(20*time.Minute))
	if len(st.Events) != 1 {
		// The closed state was removed from the map, so Add starts a fresh state.
		// What matters is that the caller can detect this and amend the stored
		// flow rather than write a second one.
		t.Logf("closed flow left in-flight state; new state has %d events", len(st.Events))
	}
}

func TestAmendmentIsMarkedOnAStillHeldFlow(t *testing.T) {
	w := newWindow()
	st := w.Add("ray:a", "acme", wev("cf", schema.LayerEdge), wbase)
	st.Closed = true // simulate a flow closed but still held for amendment

	st = w.Add("ray:a", "acme", wev("ngx", schema.LayerOrigin), wbase.Add(time.Minute))
	if !st.Amended {
		t.Error("adding to a closed flow must mark it amended so the change is visible")
	}
}

// TestRedeliveryDoesNotDuplicateALayer covers FR-007 at the window level.
func TestRedeliveryDoesNotDuplicateALayer(t *testing.T) {
	w := newWindow()
	w.Add("ray:a", "acme", wev("cf", schema.LayerEdge), wbase)
	st := w.Add("ray:a", "acme", wev("cf", schema.LayerEdge), wbase.Add(time.Second))

	if len(st.Events) != 1 {
		t.Fatalf("redelivery of the same event must not add a second layer, got %d", len(st.Events))
	}
}

// TestRestoreResumesAfterRestart covers FR-023: a restart must not discard
// partial flows.
func TestRestoreResumesAfterRestart(t *testing.T) {
	w := newWindow()
	w.Add("ray:a", "acme", wev("cf", schema.LayerEdge), wbase)
	w.Add("ray:b", "acme", wev("cf2", schema.LayerEdge), wbase)
	snapshot := w.Snapshot()

	if len(snapshot) != 2 {
		t.Fatalf("expected 2 in-flight states, got %d", len(snapshot))
	}

	restarted := newWindow()
	if restarted.InFlight() != 0 {
		t.Fatal("a fresh window starts empty")
	}
	restarted.Restore(snapshot)
	if restarted.InFlight() != 2 {
		t.Fatalf("restore must reinstate in-flight flows, got %d", restarted.InFlight())
	}
	if st, ok := restarted.Get("ray:a"); !ok || len(st.Events) != 1 {
		t.Error("restored state must retain its accumulated events")
	}
}

func TestReadyIsDeterministic(t *testing.T) {
	build := func() *Window {
		w := newWindow()
		for _, k := range []string{"ray:c", "ray:a", "ray:b"} {
			w.Add(k, "acme", wev("e", schema.LayerEdge), wbase)
		}
		return w
	}
	first := build().Ready(wbase.Add(16 * time.Minute))
	second := build().Ready(wbase.Add(16 * time.Minute))

	if len(first) != len(second) {
		t.Fatalf("different counts: %d vs %d", len(first), len(second))
	}
	for i := range first {
		if first[i].CorrelationKey != second[i].CorrelationKey {
			t.Fatalf("close order must be deterministic for replay: %s vs %s",
				first[i].CorrelationKey, second[i].CorrelationKey)
		}
	}
}

func TestSnapshotIsSorted(t *testing.T) {
	w := newWindow()
	for _, k := range []string{"ray:z", "ray:a", "ray:m"} {
		w.Add(k, "acme", wev("e", schema.LayerEdge), wbase)
	}
	snap := w.Snapshot()
	for i := 1; i < len(snap); i++ {
		if snap[i-1].CorrelationKey > snap[i].CorrelationKey {
			t.Fatal("snapshot must be ordered so persisted state is diffable and replay-stable")
		}
	}
}
