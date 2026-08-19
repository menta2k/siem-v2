package observability

import (
	"sync"
)

// CorrelationQuality tracks how flows are being joined.
//
// This is the metric FR-072e exists for, and the one most likely to degrade
// silently: flows keep forming, searches keep returning results, and nothing
// looks wrong while confidence quietly falls. A falling exact-join ratio means
// identifier propagation broke somewhere upstream.
type CorrelationQuality struct {
	mu           sync.RWMutex
	exact        int64
	heuristic    int64
	ambiguous    int64
	uncorrelated int64
	bridged      int64
}

func NewCorrelationQuality() *CorrelationQuality { return &CorrelationQuality{} }

func (c *CorrelationQuality) RecordExact(bridged bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.exact++
	if bridged {
		c.bridged++
	}
}

func (c *CorrelationQuality) RecordHeuristic()    { c.add(&c.heuristic) }
func (c *CorrelationQuality) RecordAmbiguous()    { c.add(&c.ambiguous) }
func (c *CorrelationQuality) RecordUncorrelated() { c.add(&c.uncorrelated) }

func (c *CorrelationQuality) add(counter *int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	*counter++
}

// Snapshot is the reported state.
type QualitySnapshot struct {
	ExactJoins        int64   `json:"exact_joins"`
	HeuristicJoins    int64   `json:"heuristic_joins"`
	Ambiguous         int64   `json:"ambiguous"`
	Uncorrelated      int64   `json:"uncorrelated"`
	BridgedJoins      int64   `json:"bridged_joins"`
	Total             int64   `json:"total"`
	ExactJoinRatio    float64 `json:"exact_join_ratio"`
	HeuristicRatio    float64 `json:"heuristic_ratio"`
	AmbiguousRatio    float64 `json:"ambiguous_ratio"`
	UncorrelatedRatio float64 `json:"uncorrelated_ratio"`
	// Meaningful is false until enough flows have formed for the ratios to mean
	// anything. Alerting on a 0% exact-join rate observed over three flows would
	// page someone every time the system restarts.
	Meaningful bool `json:"meaningful"`
}

// minSampleForRatio is the point at which the ratios stop being noise.
const minSampleForRatio = 100

func (c *CorrelationQuality) Snapshot() QualitySnapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()

	total := c.exact + c.heuristic + c.ambiguous + c.uncorrelated
	s := QualitySnapshot{
		ExactJoins: c.exact, HeuristicJoins: c.heuristic,
		Ambiguous: c.ambiguous, Uncorrelated: c.uncorrelated,
		BridgedJoins: c.bridged, Total: total,
		Meaningful: total >= minSampleForRatio,
	}
	if total > 0 {
		s.ExactJoinRatio = float64(c.exact) / float64(total)
		s.HeuristicRatio = float64(c.heuristic) / float64(total)
		s.AmbiguousRatio = float64(c.ambiguous) / float64(total)
		s.UncorrelatedRatio = float64(c.uncorrelated) / float64(total)
	}
	return s
}

// Reset clears the counters, used when starting a new measurement window.
func (c *CorrelationQuality) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.exact, c.heuristic, c.ambiguous, c.uncorrelated, c.bridged = 0, 0, 0, 0, 0
}
