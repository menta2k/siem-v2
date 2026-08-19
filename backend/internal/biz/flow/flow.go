// Package flow assembles correlated events into request flows.
package flow

import (
	"time"

	"github.com/menta2k/siem-v2/backend/internal/correlate/keys"
	"github.com/menta2k/siem-v2/backend/internal/normalize/schema"
)

// Completeness describes how much of a request's path a flow actually captured.
type Completeness string

const (
	// Complete: every layer we expected to hear from reported.
	Complete Completeness = "complete"
	// Partial: the late-arrival window elapsed with layers still missing. The
	// flow is usable; the gaps are named explicitly (FR-019).
	Partial Completeness = "partial"
	// Ambiguous: more than one candidate matched equally well and we refused to
	// guess (FR-021).
	Ambiguous Completeness = "ambiguous"
)

// Flow is the materialized correlated unit — the primary read object.
//
// It is materialized at ingest rather than assembled at query time because
// LogsQL's join pipe buffers the joined side in RAM, which does not survive
// SIEM-scale windows (research.md R5).
type Flow struct {
	FlowID         string         `json:"flow_id"`
	Tenant         string         `json:"tenant"`
	CorrelationKey string         `json:"correlation_key"`
	Events         []schema.Event `json:"events"`
	LayersPresent  []schema.Layer `json:"layers_present"`
	LayersMissing  []schema.Layer `json:"layers_missing"`
	Completeness   Completeness   `json:"completeness"`
	Method         keys.Tier      `json:"correlation_method"`
	Confidence     float64        `json:"correlation_confidence"`
	Bridged        bool           `json:"bridged"`

	EffectiveOutcome schema.Action `json:"effective_outcome"`
	TerminatingLayer schema.Layer  `json:"terminating_layer,omitempty"`

	FirstSeen time.Time  `json:"first_seen"`
	LastSeen  time.Time  `json:"last_seen"`
	ClosedAt  *time.Time `json:"closed_at,omitempty"`

	TimingAttribution map[schema.Layer]float64 `json:"timing_attribution,omitempty"`
	Amended           bool                     `json:"amended"`
	DataQualityFlags  []schema.QualityFlag     `json:"data_quality_flags,omitempty"`

	// Client and Request are denormalized from the most authoritative event so
	// that search results can be rendered without loading every event.
	Client  schema.Client  `json:"client"`
	Request schema.Request `json:"request"`
}

// HasFlag reports whether the flow carries a quality flag.
func (f *Flow) HasFlag(flag schema.QualityFlag) bool {
	for _, got := range f.DataQualityFlags {
		if got == flag {
			return true
		}
	}
	return false
}

func (f *Flow) addFlag(flag schema.QualityFlag) {
	if !f.HasFlag(flag) {
		f.DataQualityFlags = append(f.DataQualityFlags, flag)
	}
}
