package window

import (
	"testing"
	"time"

	"github.com/menta2k/siem-v2/backend/internal/normalize/schema"
)

var evSeq int

// ev builds a distinct event each call: Add is idempotent by EventID, so a
// shared id would silently drop the second layer.
func ev(layer schema.Layer, terminating bool) schema.Event {
	evSeq++
	return schema.Event{
		EventID: string(layer) + "-" + string(rune('a'+evSeq)),
		Layer:   layer,
		Verdict: schema.Verdict{Terminating: terminating},
	}
}

// An edge block closes on the next tick, long before the 10m window — the origin
// will never report, so there is nothing to wait for.
func TestEdgeBlockClosesEarly(t *testing.T) {
	w := New(Options{LateArrival: 10 * time.Minute, ExpectedLayers: 4})
	t0 := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	w.Add("ray:x", "default", ev(schema.LayerEdge, true), t0)

	ready := w.Ready(t0.Add(5 * time.Second))
	if len(ready) != 1 {
		t.Fatalf("edge block should close early, got %d ready", len(ready))
	}
}

// A DataDome block waits only for its upstream edge record, then closes — it
// does not wait for F5/nginx, which never see a blocked request.
func TestDataDomeBlockClosesOnceEdgePresent(t *testing.T) {
	w := New(Options{LateArrival: 10 * time.Minute, ExpectedLayers: 4})
	t0 := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)

	// Only the bot verdict so far: upstream edge record not in yet.
	w.Add("ray:y", "default", ev(schema.LayerBotManagement, true), t0)
	if got := len(w.Ready(t0.Add(5 * time.Second))); got != 0 {
		t.Fatalf("must wait for the upstream edge layer, closed %d early", got)
	}

	// Edge arrives: orders 0 and 1 present, stop at 1 → complete.
	w.Add("ray:y", "default", ev(schema.LayerEdge, false), t0.Add(6*time.Second))
	if got := len(w.Ready(t0.Add(7 * time.Second))); got != 1 {
		t.Fatalf("bot block should close once edge is present, got %d", got)
	}
}

// An F5 block with no DataDome layer present stays open: order 1 is missing, so
// it is not yet terminally complete and must wait the window.
func TestBlockMissingUpstreamLayerWaits(t *testing.T) {
	w := New(Options{LateArrival: 10 * time.Minute, ExpectedLayers: 4})
	t0 := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	w.Add("ray:z", "default", ev(schema.LayerEdge, false), t0)
	w.Add("ray:z", "default", ev(schema.LayerAppFirewall, true), t0) // stop=2, order 1 absent

	if got := len(w.Ready(t0.Add(5 * time.Second))); got != 0 {
		t.Fatalf("block missing an upstream layer must wait, closed %d early", got)
	}
	// But the full window still closes it.
	if got := len(w.Ready(t0.Add(11 * time.Minute))); got != 1 {
		t.Fatalf("window timeout must still close it, got %d", got)
	}
}

// An allowed flow with no terminating record is never closed early by this path.
func TestAllowedFlowNotClosedByTerminalPath(t *testing.T) {
	w := New(Options{LateArrival: 10 * time.Minute, ExpectedLayers: 4})
	t0 := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	w.Add("ray:a", "default", ev(schema.LayerEdge, false), t0)
	w.Add("ray:a", "default", ev(schema.LayerBotManagement, false), t0)
	if got := len(w.Ready(t0.Add(5 * time.Second))); got != 0 {
		t.Fatalf("allowed partial flow must not close early, closed %d", got)
	}
}
