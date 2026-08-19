package alerting

import (
	"math"
	"sync"
)

// Baseline tracks a rule's normal block rate so a deviation can be recognised.
//
// The point is not to detect blocking — that is expected — but to notice when a
// rule that normally blocks rarely suddenly blocks a lot. That pattern is the
// signature of a false positive reaching production, and it is invisible without
// a baseline to compare against (FR-047).
type Baseline struct {
	mu    sync.RWMutex
	stats map[string]*ruleStats
	// MinObservations is the point at which a baseline is trustworthy. Alerting
	// before then would fire on a rule's first few matches, which is noise.
	MinObservations int
	// DeviationFactor is how many times the baseline rate counts as a spike.
	DeviationFactor float64
}

type ruleStats struct {
	observations int
	blocks       int
	// mean and m2 support Welford's online variance, so the baseline updates
	// incrementally rather than needing the full history in memory.
	mean float64
	m2   float64
}

func NewBaseline() *Baseline {
	return &Baseline{
		stats:           map[string]*ruleStats{},
		MinObservations: 100,
		DeviationFactor: 3.0,
	}
}

// Observe records one evaluation of a rule.
func (b *Baseline) Observe(ruleID string, blocked bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	s, ok := b.stats[ruleID]
	if !ok {
		s = &ruleStats{}
		b.stats[ruleID] = s
	}
	s.observations++
	value := 0.0
	if blocked {
		s.blocks++
		value = 1.0
	}
	// Welford's algorithm.
	delta := value - s.mean
	s.mean += delta / float64(s.observations)
	s.m2 += delta * (value - s.mean)
}

// Deviation describes a rule behaving unlike itself.
type Deviation struct {
	RuleID       string
	CurrentRate  float64
	BaselineRate float64
	Observations int
	Factor       float64
}

// Check reports whether a rule's recent block rate deviates from its baseline.
//
// Returns false while the baseline is still forming. A rule with twelve
// observations has no meaningful normal, and treating its first spike as an
// anomaly is how this kind of detection loses credibility.
func (b *Baseline) Check(ruleID string, recentRate float64) (Deviation, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	s, ok := b.stats[ruleID]
	if !ok || s.observations < b.MinObservations {
		return Deviation{}, false
	}

	baseline := s.mean
	// A rule that has never blocked has no rate to multiply. Any blocking at all
	// is the deviation, so it is compared against a floor rather than zero.
	if baseline <= 0 {
		if recentRate > 0.01 {
			return Deviation{
				RuleID: ruleID, CurrentRate: recentRate, BaselineRate: 0,
				Observations: s.observations, Factor: math.Inf(1),
			}, true
		}
		return Deviation{}, false
	}

	factor := recentRate / baseline
	if factor < b.DeviationFactor {
		return Deviation{}, false
	}
	return Deviation{
		RuleID: ruleID, CurrentRate: recentRate, BaselineRate: baseline,
		Observations: s.observations, Factor: factor,
	}, true
}

// Rate returns a rule's established block rate.
func (b *Baseline) Rate(ruleID string) (float64, int) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	s, ok := b.stats[ruleID]
	if !ok {
		return 0, 0
	}
	return s.mean, s.observations
}
