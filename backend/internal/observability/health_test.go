package observability

import (
	"testing"
	"time"
)

var hbase = time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)

// TestSilentSourceDetected is the alert that catches the most common real SIEM
// failure: a feed quietly stops and every dashboard still looks fine.
func TestSilentSourceDetected(t *testing.T) {
	r := NewRegistry()
	r.RegisterSource("cf-1", "cloudflare", 5*time.Minute)
	r.RecordDelivery("cf-1", 100, hbase)

	if silent := r.EvaluateSilence(hbase.Add(2 * time.Minute)); len(silent) != 0 {
		t.Fatalf("within cadence the source is healthy, got %v", silent)
	}
	silent := r.EvaluateSilence(hbase.Add(10 * time.Minute))
	if len(silent) != 1 || silent[0].SourceID != "cf-1" {
		t.Fatalf("past its cadence the source must be reported silent, got %v", silent)
	}
	if r.Overall() != StateDegraded {
		t.Error("a silent source degrades overall health; the UI must not look clean")
	}
}

// TestNeverDeliveredIsAwaitingNotSilent: these need different operator responses,
// and conflating them trains people to ignore the alert.
func TestNeverDeliveredIsAwaitingNotSilent(t *testing.T) {
	r := NewRegistry()
	r.RegisterSource("new-1", "f5asm", time.Minute)

	if silent := r.EvaluateSilence(hbase.Add(time.Hour)); len(silent) != 0 {
		t.Fatal("a source that never delivered is not 'silent'; nobody has switched it on yet")
	}
	if r.Sources()[0].State != StateAwaiting {
		t.Errorf("state should be awaiting_first_record, got %q", r.Sources()[0].State)
	}
}

// TestZeroOutputWhileInputFlows is the condition a liveness probe cannot see and
// the reason Principle IV requires semantic health checks.
func TestZeroOutputWhileInputFlows(t *testing.T) {
	r := NewRegistry()
	r.UpdateStage("correlate", 5000, 0, 12000, 120)

	stages := r.ZeroOutputStages()
	if len(stages) != 1 {
		t.Fatalf("input flowing with no output must be flagged, got %v", stages)
	}
	if stages[0].State != StageZeroOutput {
		t.Errorf("state: got %q", stages[0].State)
	}
	if r.Overall() != StateDegraded {
		t.Error("a dead stage must degrade overall health even though the process is alive")
	}
}

func TestIdleStageIsNotZeroOutput(t *testing.T) {
	r := NewRegistry()
	// No input and no output is an idle pipeline, not a broken one.
	r.UpdateStage("correlate", 0, 0, 0, 0)
	if len(r.ZeroOutputStages()) != 0 {
		t.Fatal("zero input and zero output is idle; alerting on it would cry wolf every quiet night")
	}
}

func TestBacklogDetected(t *testing.T) {
	r := NewRegistry()
	r.BacklogThreshold = 1000
	r.UpdateStage("normalize", 5000, 4800, 50000, 900)

	stages := r.Stages()
	if len(stages) != 1 || stages[0].State != StageBacklogged {
		t.Fatalf("a growing backlog must be visible, got %+v", stages)
	}
}

func TestHealthyPipelineReportsHealthy(t *testing.T) {
	r := NewRegistry()
	r.RegisterSource("cf-1", "cloudflare", 5*time.Minute)
	r.RecordDelivery("cf-1", 100, hbase)
	r.UpdateStage("correlate", 5000, 4990, 12, 40)

	r.EvaluateSilence(hbase.Add(time.Minute))
	if r.Overall() != StateHealthy {
		t.Errorf("a working pipeline must report healthy, got %q", r.Overall())
	}
}

func TestParseFailureRateTracked(t *testing.T) {
	r := NewRegistry()
	r.RegisterSource("ngx-1", "nginx", time.Minute)
	r.RecordParseFailureRate("ngx-1", 0.023)
	if got := r.Sources()[0].ParseFailRate; got != 0.023 {
		t.Errorf("parse failure rate: got %v", got)
	}
}

func TestConcurrentAccessIsSafe(t *testing.T) {
	r := NewRegistry()
	r.RegisterSource("cf-1", "cloudflare", time.Minute)
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func() {
			for j := 0; j < 200; j++ {
				r.RecordDelivery("cf-1", 1, hbase)
				r.UpdateStage("correlate", 100, 90, 5, 10)
				_ = r.Overall()
				_ = r.Sources()
				r.EvaluateSilence(hbase)
			}
			done <- struct{}{}
		}()
	}
	for i := 0; i < 8; i++ {
		<-done
	}
}

// TestReRegisteringKeepsTheHistory: the feed ingest path registers its source
// on EVERY accepted delivery. If registration wipes LastRecordAt, a source's
// silence clock resets on the very event that should feed it.
func TestReRegisteringKeepsTheHistory(t *testing.T) {
	r := NewRegistry()
	r.RegisterSource("feed-1", "nginx", 15*time.Minute)
	r.RecordDelivery("feed-1", 10, time.Now().Add(-time.Hour))

	r.RegisterSource("feed-1", "nginx", 15*time.Minute) // next delivery's hook

	silent := r.EvaluateSilence(time.Now())
	if len(silent) != 1 || silent[0].SourceID != "feed-1" {
		t.Fatalf("an hour-silent source must be reported even after re-registration, got %v", silent)
	}
	if r.Overall() != StateDegraded {
		t.Fatal("a silent source must degrade overall health")
	}
}

// TestSourcesExposesStateForSyncing: the PG sync loop reads the registry's
// full view; states must reflect the last evaluation.
func TestSourcesExposesStateForSyncing(t *testing.T) {
	r := NewRegistry()
	r.RegisterSource("feed-a", "nginx", 15*time.Minute)
	r.RecordDelivery("feed-a", 5, time.Now().Add(-time.Hour))
	r.EvaluateSilence(time.Now())
	list := r.Sources()
	if len(list) != 1 || list[0].State != StateSilent {
		t.Fatalf("Sources() must carry the evaluated state, got %+v", list)
	}
}
