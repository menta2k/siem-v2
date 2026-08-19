//go:build scenario

package scenarios

import (
	"testing"
	"time"

	"github.com/menta2k/siem-v2/backend/internal/alerting"
	"github.com/menta2k/siem-v2/backend/internal/alerting/detections"
	"github.com/menta2k/siem-v2/backend/internal/observability"
)

// TestPipelineHealthScenario is S6 from quickstart.md: the constitution's
// Principle IV exercised end to end — a green dashboard over a dead pipeline
// must fail here.
//
// It drives the REAL registry and the REAL detections through the synthetic
// conditions the quickstart names: a provider feed stops, and a stage stalls
// while ingest continues. Each must alert; a healthy baseline must not.
func TestPipelineHealthScenario(t *testing.T) {
	base := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)

	registry := observability.NewRegistry()
	rules := alerting.NewRegistry()
	for _, d := range detections.All() {
		if err := rules.Activate(d); err != nil {
			t.Fatalf("activate %s: %v", d.ID, err)
		}
	}

	// --- Healthy baseline: four sources delivering, stages flowing.
	for _, src := range []string{"cf-1", "dd-1", "f5-1", "ngx-1"} {
		registry.RegisterSource(src, src, 5*time.Minute)
		registry.RecordDelivery(src, 500, base)
	}
	registry.UpdateStage("normalize", 2000, 1995, 40, 12)
	registry.UpdateStage("correlate", 1995, 1990, 15, 30)

	if fired := evaluateAll(rules, registry, base.Add(time.Minute)); len(fired) != 0 {
		t.Fatalf("a healthy baseline must raise nothing, got %v", fired)
	}

	// --- Condition 1: one provider goes silent past its cadence.
	// Everything else keeps delivering, so the dashboards would look normal.
	later := base.Add(10 * time.Minute)
	for _, src := range []string{"cf-1", "dd-1", "ngx-1"} {
		registry.RecordDelivery(src, 500, later) // f5-1 deliberately absent
	}
	fired := evaluateAll(rules, registry, later)
	if !firedFor(fired, "pipeline.source_silence", "f5-1") {
		t.Fatalf("a silent f5-1 must raise source_silence within its cadence, got %v", fired)
	}
	if firedFor(fired, "pipeline.source_silence", "cf-1") {
		t.Error("a delivering source must not be reported silent")
	}

	// --- Condition 2: the correlation stage stalls while ingest continues.
	// Every process is alive; every liveness probe passes. This is the condition
	// the constitution's semantic health checks exist for.
	registry.UpdateStage("correlate", 1995, 0, 90000, 0)
	fired = evaluateAll(rules, registry, later)
	if !firedFor(fired, "pipeline.stage_zero_output", "correlate") {
		t.Fatalf("input flowing with zero output must alert, got %v", fired)
	}

	// --- Recovery: the feed and the stage come back; the conditions clear.
	registry.RecordDelivery("f5-1", 200, later.Add(time.Minute))
	registry.UpdateStage("correlate", 1995, 1990, 20, 30)
	if fired := evaluateAll(rules, registry, later.Add(2*time.Minute)); len(fired) != 0 {
		t.Fatalf("after recovery nothing should fire, got %v", fired)
	}
}

// evaluateAll converts the registry's state into detection subjects and runs
// every rule — the same wiring the alerting loop performs in production.
func evaluateAll(rules *alerting.Registry, reg *observability.Registry, now time.Time) []string {
	var fired []string

	reg.EvaluateSilence(now)
	for _, src := range reg.Sources() {
		delivered := 0.0
		since := 0.0
		if !src.LastRecordAt.IsZero() {
			delivered = 1
			since = now.Sub(src.LastRecordAt).Seconds()
		}
		subject := alerting.Subject{
			Kind: alerting.SubjectSourceHealth, Tenant: "acme", At: now,
			Attributes: map[string]any{"source_id": src.SourceID},
			NumericVals: map[string]float64{
				"has_delivered":             delivered,
				"seconds_since_last_record": since,
				"expected_cadence_seconds":  src.ExpectedCadence.Seconds(),
				"parse_failure_rate":        src.ParseFailRate,
			},
		}
		for _, d := range rules.Evaluate(subject) {
			fired = append(fired, d.ID+":"+src.SourceID)
		}
	}
	for _, st := range reg.Stages() {
		subject := alerting.Subject{
			Kind: alerting.SubjectStageHealth, Tenant: "acme", At: now,
			Attributes: map[string]any{"stage": st.Stage},
			NumericVals: map[string]float64{
				"input_rate": st.InputRate, "output_rate": st.OutputRate,
			},
		}
		for _, d := range rules.Evaluate(subject) {
			fired = append(fired, d.ID+":"+st.Stage)
		}
	}
	return fired
}

func firedFor(fired []string, detection, subject string) bool {
	want := detection + ":" + subject
	for _, f := range fired {
		if f == want {
			return true
		}
	}
	return false
}
