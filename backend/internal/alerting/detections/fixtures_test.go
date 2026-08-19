package detections

import (
	"strings"
	"testing"

	"github.com/menta2k/siem-v2/backend/internal/alerting"
)

// TestDetectionFixtures is the Constitution III gate, wired into CI via
// `make test-detections`. Every built-in detection must fire on its positive
// fixture and stay silent on its near-miss.
func TestDetectionFixtures(t *testing.T) {
	all := All()
	if len(all) == 0 {
		t.Fatal("no built-in detections registered")
	}
	for _, d := range all {
		t.Run(d.ID, func(t *testing.T) {
			if err := alerting.ValidateFixtures(d); err != nil {
				t.Fatalf("fixture validation failed: %v", err)
			}
		})
	}
}

// TestEveryDetectionCarriesItsOwnFirstStep: an alert that arrives without a
// first step sends the responder hunting, which is how alerts get ignored.
func TestEveryDetectionCarriesItsOwnFirstStep(t *testing.T) {
	for _, d := range All() {
		if strings.TrimSpace(d.RecommendedFirstCheck) == "" {
			t.Errorf("detection %q has no recommended first check", d.ID)
		}
		if strings.TrimSpace(d.ExpectedResponse) == "" {
			t.Errorf("detection %q has no expected response", d.ID)
		}
		if strings.TrimSpace(d.Hypothesis) == "" {
			t.Errorf("detection %q has no hypothesis", d.ID)
		}
		if d.Version == "" {
			t.Errorf("detection %q has no version; alerts must name the version that fired", d.ID)
		}
	}
}

// TestActivationRefusesUnprovenDetections proves the gate is a refusal, not a
// warning.
func TestActivationRefusesUnprovenDetections(t *testing.T) {
	r := alerting.NewRegistry()

	noFixtures := alerting.Detection{
		ID: "bad.no_fixtures", Version: "1.0", Hypothesis: "something",
		Condition: func(alerting.Subject) bool { return true },
		Enabled:   true,
	}
	if err := r.Activate(noFixtures); err == nil {
		t.Error("a detection with no fixtures must be refused activation")
	}

	// The case the near-miss requirement exists for: a rule that fires on
	// everything passes its positive fixture perfectly.
	firesOnEverything := alerting.Detection{
		ID: "bad.fires_on_everything", Version: "1.0", Hypothesis: "everything is bad",
		Condition: func(alerting.Subject) bool { return true },
		Enabled:   true,
		Fixtures: alerting.Fixtures{
			Positive: []alerting.Subject{{Kind: alerting.SubjectFlow}},
			NearMiss: []alerting.Subject{{Kind: alerting.SubjectFlow}},
		},
	}
	err := r.Activate(firesOnEverything)
	if err == nil {
		t.Fatal("a rule that fires on its own near-miss does not discriminate and must be refused")
	}
	if !strings.Contains(err.Error(), "near-miss") {
		t.Errorf("the refusal should name the near-miss failure, got: %v", err)
	}

	neverFires := alerting.Detection{
		ID: "bad.never_fires", Version: "1.0", Hypothesis: "nothing is bad",
		Condition: func(alerting.Subject) bool { return false },
		Enabled:   true,
		Fixtures: alerting.Fixtures{
			Positive: []alerting.Subject{{Kind: alerting.SubjectFlow}},
			NearMiss: []alerting.Subject{{Kind: alerting.SubjectFlow}},
		},
	}
	if err := r.Activate(neverFires); err == nil {
		t.Error("a detection that does not fire on its own positive fixture must be refused")
	}

	if len(r.All()) != 0 {
		t.Fatal("no unproven detection may reach the registry")
	}
}

func TestBuiltinsActivate(t *testing.T) {
	r := alerting.NewRegistry()
	for _, d := range All() {
		if err := r.Activate(d); err != nil {
			t.Errorf("built-in %q failed activation: %v", d.ID, err)
		}
	}
	if len(r.All()) != len(All()) {
		t.Errorf("expected %d activated, got %d", len(All()), len(r.All()))
	}
}

// TestSilenceDoesNotFireOnANewSource guards the distinction that keeps this
// alert credible.
func TestSilenceDoesNotFireOnANewSource(t *testing.T) {
	r := alerting.NewRegistry()
	if err := r.Activate(SourceSilence()); err != nil {
		t.Fatalf("activate: %v", err)
	}
	brandNew := alerting.Subject{
		Kind: alerting.SubjectSourceHealth,
		NumericVals: map[string]float64{
			"has_delivered": 0, "seconds_since_last_record": 86400, "expected_cadence_seconds": 60,
		},
	}
	if fired := r.Evaluate(brandNew); len(fired) != 0 {
		t.Fatal("a source that never delivered must not raise a silence alert")
	}
}

// TestZeroOutputDoesNotFireWhenIdle guards against the alert that would get muted.
func TestZeroOutputDoesNotFireWhenIdle(t *testing.T) {
	r := alerting.NewRegistry()
	if err := r.Activate(StageZeroOutput()); err != nil {
		t.Fatalf("activate: %v", err)
	}
	idle := alerting.Subject{
		Kind:        alerting.SubjectStageHealth,
		NumericVals: map[string]float64{"input_rate": 0, "output_rate": 0},
	}
	if fired := r.Evaluate(idle); len(fired) != 0 {
		t.Fatal("an idle pipeline is not a stalled one")
	}

	stalled := alerting.Subject{
		Kind:        alerting.SubjectStageHealth,
		NumericVals: map[string]float64{"input_rate": 4000, "output_rate": 0},
	}
	if fired := r.Evaluate(stalled); len(fired) != 1 {
		t.Fatal("a stalled stage must fire")
	}
}

func TestDisabledDetectionsDoNotFire(t *testing.T) {
	r := alerting.NewRegistry()
	d := StageZeroOutput()
	d.Enabled = false
	if err := r.Activate(d); err != nil {
		t.Fatalf("activate: %v", err)
	}
	stalled := alerting.Subject{
		Kind:        alerting.SubjectStageHealth,
		NumericVals: map[string]float64{"input_rate": 4000, "output_rate": 0},
	}
	if fired := r.Evaluate(stalled); len(fired) != 0 {
		t.Fatal("a disabled detection must not fire")
	}
}
