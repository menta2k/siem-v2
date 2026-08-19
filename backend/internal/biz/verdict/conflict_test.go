package verdict

import (
	"testing"

	"github.com/menta2k/siem-v2/backend/internal/normalize/schema"
)

func ev(layer schema.Layer, action schema.Action, mapped bool) schema.Event {
	return schema.Event{
		Layer: layer, Provider: schema.ProviderCloudflare,
		Verdict: schema.Verdict{Action: action, Mapped: mapped, Terminating: action.Terminal()},
	}
}

func f64(v float64) *float64 { return &v }
func i(v int) *int           { return &v }

// TestScoreConflictOnAllowedRequest is the signal that justifies the whole
// system: no single console can show it.
func TestScoreConflictOnAllowedRequest(t *testing.T) {
	e := ev(schema.LayerBotManagement, schema.ActionAllowed, true)
	e.Bot = &schema.Bot{DataDomePresent: true, DataDomeScore: f64(4)}

	conflicts := Analyse([]schema.Event{e})
	if len(conflicts) != 1 || conflicts[0].Kind != ScoreConflict {
		t.Fatalf("a low bot score on an allowed request must be flagged, got %+v", conflicts)
	}
}

func TestHighScoreOnAllowedRequestIsNotAConflict(t *testing.T) {
	e := ev(schema.LayerBotManagement, schema.ActionAllowed, true)
	e.Bot = &schema.Bot{DataDomePresent: true, DataDomeScore: f64(95)}

	if conflicts := Analyse([]schema.Event{e}); len(conflicts) != 0 {
		t.Fatalf("a human-looking score on an allowed request is ordinary, got %+v", conflicts)
	}
}

// TestBlockedAfterAllowIsHighSeverity: the outer layer let through what the
// inner one caught, which is a gap rather than a mere disagreement.
func TestBlockedAfterAllowIsHighSeverity(t *testing.T) {
	events := []schema.Event{
		ev(schema.LayerEdge, schema.ActionAllowed, true),
		ev(schema.LayerAppFirewall, schema.ActionBlocked, true),
	}
	conflicts := Analyse(events)

	var found bool
	for _, c := range conflicts {
		if c.Kind == BlockedAfterAllow {
			found = true
			if c.Severity != "high" {
				t.Errorf("a gap in the outer layer is high severity, got %q", c.Severity)
			}
		}
	}
	if !found {
		t.Fatalf("expected a blocked-after-allow conflict, got %+v", conflicts)
	}
}

func TestUnanimousAllowHasNoConflicts(t *testing.T) {
	events := []schema.Event{
		ev(schema.LayerEdge, schema.ActionAllowed, true),
		ev(schema.LayerAppFirewall, schema.ActionAllowed, true),
		ev(schema.LayerOrigin, schema.ActionAllowed, true),
	}
	if conflicts := Analyse(events); len(conflicts) != 0 {
		t.Fatalf("agreement is not a conflict, got %+v", conflicts)
	}
}

func TestUnanimousBlockHasNoDisagreement(t *testing.T) {
	events := []schema.Event{
		ev(schema.LayerEdge, schema.ActionBlocked, true),
		ev(schema.LayerAppFirewall, schema.ActionBlocked, true),
	}
	for _, c := range Analyse(events) {
		if c.Kind == LayerDisagreement {
			t.Fatal("layers agreeing to block is not a disagreement")
		}
	}
}

func TestUnmappedVerdictIsSurfaced(t *testing.T) {
	events := []schema.Event{ev(schema.LayerEdge, schema.ActionUnknown, false)}
	conflicts := Analyse(events)
	if len(conflicts) != 1 || conflicts[0].Kind != UnmappedVerdict {
		t.Fatalf("an unrecognized verdict must be surfaced, got %+v", conflicts)
	}
}

// TestCloudflareBotScoreScoredSeparately: CF and DataDome scores mean different
// things and must not be conflated.
func TestCloudflareBotScoreScoredSeparately(t *testing.T) {
	e := ev(schema.LayerEdge, schema.ActionAllowed, true)
	e.Bot = &schema.Bot{CFBotScore: i(3)}

	conflicts := Analyse([]schema.Event{e})
	if len(conflicts) != 1 || conflicts[0].Kind != ScoreConflict {
		t.Fatalf("a low Cloudflare bot score on an allow is a conflict, got %+v", conflicts)
	}
	if conflicts[0].Severity != "low" {
		t.Errorf("a CF bot score is weaker evidence than a DataDome score, got %q", conflicts[0].Severity)
	}
}

func TestNoBotDataProducesNoScoreConflict(t *testing.T) {
	events := []schema.Event{ev(schema.LayerOrigin, schema.ActionAllowed, true)}
	if conflicts := Analyse(events); len(conflicts) != 0 {
		t.Fatalf("absent bot data is not evidence of anything, got %+v", conflicts)
	}
}
