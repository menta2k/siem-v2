package alerting

import "testing"

func TestBaselineFormsBeforeAlerting(t *testing.T) {
	b := NewBaseline()
	b.MinObservations = 100

	// A rule with a handful of observations has no meaningful normal.
	for i := 0; i < 20; i++ {
		b.Observe("rule-1", false)
	}
	if _, deviates := b.Check("rule-1", 1.0); deviates {
		t.Fatal("a baseline with 20 observations must not support an anomaly claim")
	}

	for i := 0; i < 200; i++ {
		b.Observe("rule-1", i%100 == 0) // ~1% block rate
	}
	if _, deviates := b.Check("rule-1", 0.012); deviates {
		t.Error("a rate close to the baseline is not a deviation")
	}
	d, deviates := b.Check("rule-1", 0.40)
	if !deviates {
		t.Fatal("a 40% block rate against a ~1% baseline must be flagged")
	}
	if d.Factor < 3 {
		t.Errorf("factor should reflect the magnitude, got %v", d.Factor)
	}
}

// TestRuleThatNeverBlockedIsHandled: multiplying a zero baseline gives no useful
// factor, so any blocking at all is the deviation.
func TestRuleThatNeverBlockedIsHandled(t *testing.T) {
	b := NewBaseline()
	b.MinObservations = 50
	for i := 0; i < 100; i++ {
		b.Observe("quiet-rule", false)
	}

	if _, deviates := b.Check("quiet-rule", 0.0); deviates {
		t.Error("still not blocking is not a deviation")
	}
	d, deviates := b.Check("quiet-rule", 0.15)
	if !deviates {
		t.Fatal("a rule that never blocked suddenly blocking 15% must be flagged")
	}
	if d.BaselineRate != 0 {
		t.Errorf("baseline should be reported as zero, got %v", d.BaselineRate)
	}
}

func TestUnknownRuleDoesNotAlert(t *testing.T) {
	b := NewBaseline()
	if _, deviates := b.Check("never-seen", 1.0); deviates {
		t.Fatal("a rule with no history cannot deviate from it")
	}
}

func TestRateReporting(t *testing.T) {
	b := NewBaseline()
	for i := 0; i < 10; i++ {
		b.Observe("r", i < 3) // 30%
	}
	rate, n := b.Rate("r")
	if n != 10 {
		t.Errorf("observations: got %d", n)
	}
	if rate < 0.29 || rate > 0.31 {
		t.Errorf("rate: got %v, want ~0.30", rate)
	}
}

func TestBaselineIsConcurrencySafe(t *testing.T) {
	b := NewBaseline()
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func(n int) {
			for j := 0; j < 300; j++ {
				b.Observe("shared", j%10 == 0)
				b.Check("shared", 0.5)
				b.Rate("shared")
			}
			done <- struct{}{}
		}(i)
	}
	for i := 0; i < 8; i++ {
		<-done
	}
	if _, n := b.Rate("shared"); n != 2400 {
		t.Errorf("expected 2400 observations, got %d", n)
	}
}
