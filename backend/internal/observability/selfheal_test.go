package observability

import (
	"context"
	"errors"
	"testing"
	"time"
)

func healer(t *testing.T) (*Healer, *[]RecoveryOutcome) {
	t.Helper()
	var outcomes []RecoveryOutcome
	h := NewHealer()
	h.Now = func() time.Time { return hbase }
	h.OnOutcome = func(o RecoveryOutcome) { outcomes = append(outcomes, o) }
	return h, &outcomes
}

func TestSuccessfulRecoveryIsReported(t *testing.T) {
	h, outcomes := healer(t)
	var ran bool
	o := h.Heal(context.Background(), Recovery{
		Name: "reconnect", MaxAttempts: 3,
		Attempt: func(context.Context) error { ran = true; return nil },
	}, "connection lost")

	if !ran || !o.Succeeded {
		t.Fatalf("recovery should have run and succeeded: %+v", o)
	}
	// Constitution IV requires every attempt logged with cause and outcome.
	if len(*outcomes) != 1 || (*outcomes)[0].Cause != "connection lost" {
		t.Fatalf("the attempt must be reported with its cause: %+v", *outcomes)
	}
}

// TestRecoveryEscalatesRatherThanLooping is the bound that keeps self-healing
// honest: a fault surviving repeated recovery is not one recovery fixes, and
// quietly retrying forever would hide it.
func TestRecoveryEscalatesRatherThanLooping(t *testing.T) {
	h, outcomes := healer(t)
	r := Recovery{
		Name: "restart", MaxAttempts: 2,
		Attempt: func(context.Context) error { return errors.New("still broken") },
	}

	h.Heal(context.Background(), r, "stalled")
	h.Heal(context.Background(), r, "stalled")
	third := h.Heal(context.Background(), r, "stalled")

	if !third.Escalated {
		t.Fatal("past its bound, recovery must escalate rather than retry")
	}
	if third.Err == nil {
		t.Error("escalation must carry a reason a human can act on")
	}
	if len(*outcomes) != 3 {
		t.Errorf("every attempt including the escalation must be reported, got %d", len(*outcomes))
	}
}

// TestSuccessResetsTheCount: an intermittent fault must not accumulate toward
// escalation over hours of otherwise healthy operation.
func TestSuccessResetsTheCount(t *testing.T) {
	h, _ := healer(t)
	fail := true
	r := Recovery{
		Name: "flaky", MaxAttempts: 2,
		Attempt: func(context.Context) error {
			if fail {
				return errors.New("nope")
			}
			return nil
		},
	}

	h.Heal(context.Background(), r, "x")
	fail = false
	h.Heal(context.Background(), r, "x")
	if h.Attempts("flaky") != 0 {
		t.Fatalf("a success must reset the count, got %d", h.Attempts("flaky"))
	}
	fail = true
	if o := h.Heal(context.Background(), r, "x"); o.Escalated {
		t.Error("after a success, the budget should be fresh")
	}
}

func TestWindowResetsAfterQuietPeriod(t *testing.T) {
	var now = hbase
	h := NewHealer()
	h.Now = func() time.Time { return now }
	r := Recovery{
		Name: "windowed", MaxAttempts: 1, Window: time.Hour,
		Attempt: func(context.Context) error { return errors.New("fail") },
	}

	h.Heal(context.Background(), r, "x")
	if o := h.Heal(context.Background(), r, "x"); !o.Escalated {
		t.Fatal("a second attempt within the window should escalate")
	}
	now = now.Add(2 * time.Hour)
	if o := h.Heal(context.Background(), r, "x"); o.Escalated {
		t.Error("after the window, this is a new incident and gets a fresh budget")
	}
}

func TestMissingAttemptFunctionIsReported(t *testing.T) {
	h, _ := healer(t)
	o := h.Heal(context.Background(), Recovery{Name: "empty"}, "x")
	if o.Err == nil {
		t.Error("a recovery with no attempt function is a configuration bug and must surface")
	}
}

func TestCorrelationQualityRatios(t *testing.T) {
	q := NewCorrelationQuality()
	for i := 0; i < 90; i++ {
		q.RecordExact(i%3 == 0)
	}
	for i := 0; i < 10; i++ {
		q.RecordHeuristic()
	}

	s := q.Snapshot()
	if s.Total != 100 {
		t.Fatalf("total: got %d", s.Total)
	}
	if s.ExactJoinRatio != 0.9 {
		t.Errorf("exact ratio: got %v", s.ExactJoinRatio)
	}
	if s.BridgedJoins != 30 {
		t.Errorf("bridged: got %d", s.BridgedJoins)
	}
	if !s.Meaningful {
		t.Error("100 samples should be enough for the ratios to mean something")
	}
}

// TestRatiosAreNotMeaningfulOnTinySamples: alerting on a 0% exact-join rate
// observed over three flows would page someone on every restart.
func TestRatiosAreNotMeaningfulOnTinySamples(t *testing.T) {
	q := NewCorrelationQuality()
	q.RecordHeuristic()
	q.RecordHeuristic()

	s := q.Snapshot()
	if s.Meaningful {
		t.Fatal("two samples cannot support a ratio")
	}
	if s.ExactJoinRatio != 0 {
		t.Errorf("the ratio is still computed, just not trusted: got %v", s.ExactJoinRatio)
	}
}

func TestCorrelationQualityReset(t *testing.T) {
	q := NewCorrelationQuality()
	q.RecordExact(true)
	q.RecordUncorrelated()
	q.RecordAmbiguous()
	q.Reset()
	if q.Snapshot().Total != 0 {
		t.Error("reset should clear every counter")
	}
}

func TestCorrelationQualityIsConcurrencySafe(t *testing.T) {
	q := NewCorrelationQuality()
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func() {
			for j := 0; j < 500; j++ {
				q.RecordExact(j%2 == 0)
				q.RecordHeuristic()
				_ = q.Snapshot()
			}
			done <- struct{}{}
		}()
	}
	for i := 0; i < 8; i++ {
		<-done
	}
	if got := q.Snapshot().Total; got != 8000 {
		t.Errorf("expected 8000 recorded, got %d", got)
	}
}
