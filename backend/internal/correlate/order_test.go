package correlate

import (
	"testing"
	"time"

	"github.com/menta2k/siem-v2/backend/internal/normalize/schema"
)

func ev(id string, layer schema.Layer, at time.Time) schema.Event {
	return schema.Event{EventID: id, Layer: layer, EventTime: at}
}

// TestOrderingIgnoresClockSkew is the scenario the spec calls out explicitly:
// the origin's clock is ahead, so a timestamp sort would claim nginx saw the
// request before Cloudflare did.
func TestOrderingIgnoresClockSkew(t *testing.T) {
	base := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	events := []schema.Event{
		// nginx clock is 5s FAST — its timestamp is earliest despite being last.
		ev("ngx", schema.LayerOrigin, base.Add(-5*time.Second)),
		ev("cf", schema.LayerEdge, base),
		ev("f5", schema.LayerAppFirewall, base.Add(2*time.Millisecond)),
		ev("dd", schema.LayerBotManagement, base.Add(1*time.Millisecond)),
	}

	got := OrderEvents(events)
	want := []string{"cf", "dd", "f5", "ngx"}
	for i, id := range want {
		if got[i].EventID != id {
			t.Fatalf("position %d: want %s, got %s (full order: %s)", i, id, got[i].EventID, ids(got))
		}
	}

	skewed, worst := DetectSkew(got)
	if !skewed {
		t.Fatal("a 5s backwards jump between layers must be reported as skew")
	}
	if worst < 5000 {
		t.Fatalf("expected worst skew >= 5000ms, got %d", worst)
	}
}

func TestOrderingIsDeterministicForIdenticalTimestamps(t *testing.T) {
	at := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	a := OrderEvents([]schema.Event{
		ev("z", schema.LayerEdge, at), ev("a", schema.LayerEdge, at)})
	b := OrderEvents([]schema.Event{
		ev("a", schema.LayerEdge, at), ev("z", schema.LayerEdge, at)})
	if a[0].EventID != b[0].EventID {
		t.Fatalf("identical timestamps must break ties deterministically, got %s vs %s", ids(a), ids(b))
	}
}

func TestUnknownLayerSortsLastRatherThanBeingMisplaced(t *testing.T) {
	base := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	got := OrderEvents([]schema.Event{
		ev("mystery", schema.Layer("future_provider"), base.Add(-time.Hour)),
		ev("cf", schema.LayerEdge, base),
		ev("ngx", schema.LayerOrigin, base.Add(time.Second)),
	})
	if got[len(got)-1].EventID != "mystery" {
		t.Fatalf("an unknown layer must sort last where it is visibly unplaced, got %s", ids(got))
	}
}

func TestNoSkewReportedWithinOneLayer(t *testing.T) {
	base := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	// Two edge events out of timestamp order come from the same clock; that is
	// not inter-system skew and must not be reported as such.
	ordered := OrderEvents([]schema.Event{
		ev("cf-b", schema.LayerEdge, base.Add(time.Second)),
		ev("cf-a", schema.LayerEdge, base),
	})
	if skewed, _ := DetectSkew(ordered); skewed {
		t.Fatal("disorder within a single layer is not clock skew between providers")
	}
}

func ids(events []schema.Event) string {
	out := ""
	for i, e := range events {
		if i > 0 {
			out += ","
		}
		out += e.EventID
	}
	return out
}
