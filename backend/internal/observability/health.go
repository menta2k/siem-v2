// Package observability implements the pipeline's view of itself.
//
// Constitution Principle IV exists because SIEM outages are usually silent: the
// dashboards stay green while zero events flow. Everything here is built to make
// "nothing is happening" as loud as "something bad is happening".
package observability

import (
	"sync"
	"time"
)

// SourceHealth is the state of one configured log source.
type SourceHealth struct {
	SourceID        string        `json:"source_id"`
	Provider        string        `json:"provider"`
	State           HealthState   `json:"state"`
	LastRecordAt    time.Time     `json:"last_record_at"`
	ExpectedCadence time.Duration `json:"expected_cadence"`
	RecordsPerSec   float64       `json:"records_per_second"`
	ParseFailRate   float64       `json:"parse_failure_rate"`
}

type HealthState string

const (
	StateHealthy  HealthState = "healthy"
	StateSilent   HealthState = "silent"
	StateDegraded HealthState = "degraded"
	// StateAwaiting distinguishes "configured but nothing yet" from "was working
	// and stopped". Treating a brand-new source as silent would page someone for
	// a source nobody has switched on.
	StateAwaiting HealthState = "awaiting_first_record"
)

// StageHealth is the state of one processing stage.
type StageHealth struct {
	Stage        string     `json:"stage"`
	State        StageState `json:"state"`
	InputRate    float64    `json:"input_rate"`
	OutputRate   float64    `json:"output_rate"`
	BacklogDepth int64      `json:"backlog_depth"`
	LatencyP95MS float64    `json:"latency_p95_ms"`
}

type StageState string

const (
	StageHealthyState StageState = "healthy"
	// StageZeroOutput is the condition a liveness probe cannot see: the process is
	// running, the input is flowing, and nothing is coming out.
	StageZeroOutput StageState = "zero_output"
	StageBacklogged StageState = "backlogged"
)

// Registry tracks per-source and per-stage health.
type Registry struct {
	mu      sync.RWMutex
	sources map[string]*SourceHealth
	stages  map[string]*StageHealth
	// BacklogThreshold is the depth above which a stage is considered backlogged.
	BacklogThreshold int64
}

func NewRegistry() *Registry {
	return &Registry{
		sources:          map[string]*SourceHealth{},
		stages:           map[string]*StageHealth{},
		BacklogThreshold: 100000,
	}
}

// RegisterSource declares a source and its expected delivery cadence. The
// cadence is what makes silence detectable: without a declared expectation,
// "quiet" and "broken" are indistinguishable.
func (r *Registry) RegisterSource(sourceID, provider string, cadence time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sources[sourceID] = &SourceHealth{
		SourceID: sourceID, Provider: provider,
		ExpectedCadence: cadence, State: StateAwaiting,
	}
}

// RecordDelivery notes that a source delivered records.
func (r *Registry) RecordDelivery(sourceID string, count int, at time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.sources[sourceID]
	if !ok {
		return
	}
	if count > 0 {
		s.LastRecordAt = at
		s.State = StateHealthy
	}
}

// RecordParseFailureRate updates a source's parse failure rate.
func (r *Registry) RecordParseFailureRate(sourceID string, rate float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.sources[sourceID]; ok {
		s.ParseFailRate = rate
	}
}

// UpdateStage records a stage's throughput.
func (r *Registry) UpdateStage(stage string, inputRate, outputRate float64, backlog int64, latencyP95 float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	st, ok := r.stages[stage]
	if !ok {
		st = &StageHealth{Stage: stage}
		r.stages[stage] = st
	}
	st.InputRate, st.OutputRate = inputRate, outputRate
	st.BacklogDepth, st.LatencyP95MS = backlog, latencyP95

	switch {
	// The condition Principle IV is written for: input flowing, output stopped,
	// process perfectly alive.
	case inputRate > 0 && outputRate == 0:
		st.State = StageZeroOutput
	case backlog > r.BacklogThreshold:
		st.State = StageBacklogged
	default:
		st.State = StageHealthyState
	}
}

// EvaluateSilence marks sources that have gone quiet past their cadence.
//
// A source that has never delivered stays "awaiting" rather than becoming
// "silent": those need different operator responses, and conflating them trains
// people to ignore the alert.
func (r *Registry) EvaluateSilence(now time.Time) []SourceHealth {
	r.mu.Lock()
	defer r.mu.Unlock()

	var silent []SourceHealth
	for _, s := range r.sources {
		if s.LastRecordAt.IsZero() {
			s.State = StateAwaiting
			continue
		}
		if s.ExpectedCadence > 0 && now.Sub(s.LastRecordAt) > s.ExpectedCadence {
			s.State = StateSilent
			silent = append(silent, *s)
		}
	}
	return silent
}

// ZeroOutputStages returns stages consuming input while producing nothing.
func (r *Registry) ZeroOutputStages() []StageHealth {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []StageHealth
	for _, st := range r.stages {
		if st.State == StageZeroOutput {
			out = append(out, *st)
		}
	}
	return out
}

// Overall summarizes system health for the frontend banner, so a user never
// reads an incomplete view as a complete one (FR-071).
func (r *Registry) Overall() HealthState {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, st := range r.stages {
		if st.State == StageZeroOutput {
			return StateDegraded
		}
	}
	for _, s := range r.sources {
		if s.State == StateSilent {
			return StateDegraded
		}
	}
	return StateHealthy
}

// Sources returns a snapshot of source health.
func (r *Registry) Sources() []SourceHealth {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]SourceHealth, 0, len(r.sources))
	for _, s := range r.sources {
		out = append(out, *s)
	}
	return out
}

// Stages returns a snapshot of stage health.
func (r *Registry) Stages() []StageHealth {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]StageHealth, 0, len(r.stages))
	for _, st := range r.stages {
		out = append(out, *st)
	}
	return out
}
