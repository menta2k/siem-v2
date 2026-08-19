// Package detections holds the built-in detection definitions.
//
// Each detection ships with a positive fixture and a near-miss fixture, and
// cannot be activated without passing both. The near-miss is where most of the
// value is: it proves the rule discriminates rather than merely fires.
package detections

import (
	"time"

	"github.com/menta2k/siem-v2/backend/internal/alerting"
)

var fixtureTime = time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)

// SourceSilence fires when a source stops delivering (FR-044).
func SourceSilence() alerting.Detection {
	const key = "seconds_since_last_record"
	condition := func(s alerting.Subject) bool {
		if s.Kind != alerting.SubjectSourceHealth {
			return false
		}
		// A source that has never delivered is "awaiting", not silent. Firing on
		// it would page someone for a feed nobody switched on.
		if delivered, ok := s.Num("has_delivered"); !ok || delivered == 0 {
			return false
		}
		since, ok := s.Num(key)
		if !ok {
			return false
		}
		cadence, ok := s.Num("expected_cadence_seconds")
		return ok && cadence > 0 && since > cadence
	}
	return alerting.Detection{
		ID: "pipeline.source_silence", Name: "Log source has gone silent",
		Version: "1.0", Severity: alerting.SeverityHigh, Category: "pipeline",
		Hypothesis: "A source that previously delivered and has now been quiet past its " +
			"expected cadence has stopped reaching us. A silent feed is indistinguishable " +
			"from clean traffic on a dashboard, which is why it must alert.",
		ExpectedResponse:      "Confirm the provider's delivery configuration and our ingest endpoint's reachability.",
		RecommendedFirstCheck: "Check the source's last_record_at and whether the provider's job or agent is still running.",
		Enabled:               true,
		Condition:             condition,
		Fixtures: alerting.Fixtures{
			Positive: []alerting.Subject{{
				Kind: alerting.SubjectSourceHealth, At: fixtureTime,
				NumericVals: map[string]float64{
					"has_delivered": 1, "seconds_since_last_record": 900, "expected_cadence_seconds": 300,
				},
			}},
			NearMiss: []alerting.Subject{
				{ // within cadence
					Kind: alerting.SubjectSourceHealth, At: fixtureTime,
					NumericVals: map[string]float64{
						"has_delivered": 1, "seconds_since_last_record": 120, "expected_cadence_seconds": 300,
					},
				},
				{ // never delivered: awaiting, not silent
					Kind: alerting.SubjectSourceHealth, At: fixtureTime,
					NumericVals: map[string]float64{
						"has_delivered": 0, "seconds_since_last_record": 99999, "expected_cadence_seconds": 300,
					},
				},
			},
		},
	}
}

// StageZeroOutput fires when a stage consumes input and produces nothing
// (FR-045). This is the condition a liveness probe cannot see.
func StageZeroOutput() alerting.Detection {
	condition := func(s alerting.Subject) bool {
		if s.Kind != alerting.SubjectStageHealth {
			return false
		}
		in, okIn := s.Num("input_rate")
		out, okOut := s.Num("output_rate")
		// Zero in AND zero out is an idle pipeline, not a broken one. Alerting on
		// idle would cry wolf every quiet night and get the rule muted.
		return okIn && okOut && in > 0 && out == 0
	}
	return alerting.Detection{
		ID: "pipeline.stage_zero_output", Name: "Processing stage produces no output",
		Version: "1.0", Severity: alerting.SeverityCritical, Category: "pipeline",
		Hypothesis: "A stage receiving input while emitting nothing has stalled, even though " +
			"every process is still running and every liveness probe still passes.",
		ExpectedResponse:      "Inspect the stage's backlog and error rate; restart or replay from the buffer.",
		RecommendedFirstCheck: "Compare the stage's input and output rates over the last five minutes.",
		Enabled:               true,
		Condition:             condition,
		Fixtures: alerting.Fixtures{
			Positive: []alerting.Subject{{
				Kind: alerting.SubjectStageHealth, At: fixtureTime,
				NumericVals: map[string]float64{"input_rate": 5000, "output_rate": 0},
			}},
			NearMiss: []alerting.Subject{
				{ // healthy
					Kind: alerting.SubjectStageHealth, At: fixtureTime,
					NumericVals: map[string]float64{"input_rate": 5000, "output_rate": 4980},
				},
				{ // genuinely idle
					Kind: alerting.SubjectStageHealth, At: fixtureTime,
					NumericVals: map[string]float64{"input_rate": 0, "output_rate": 0},
				},
			},
		},
	}
}

// ParseFailureSpike fires when a source's parse failure rate jumps, which is
// usually a provider changing its format without notice (FR-046).
func ParseFailureSpike() alerting.Detection {
	condition := func(s alerting.Subject) bool {
		if s.Kind != alerting.SubjectSourceHealth {
			return false
		}
		rate, ok := s.Num("parse_failure_rate")
		return ok && rate > 0.01 // SC-011 targets under 0.1%; 1% is well past noise
	}
	return alerting.Detection{
		ID: "pipeline.parse_failure_spike", Name: "Parse failure rate elevated",
		Version: "1.0", Severity: alerting.SeverityHigh, Category: "pipeline",
		Hypothesis: "A rising parse failure rate usually means a provider changed its log " +
			"format. The records are preserved in the dead-letter store, so this is " +
			"recoverable — but only if someone notices.",
		ExpectedResponse:      "Inspect dead-lettered records, update the parser, then reprocess.",
		RecommendedFirstCheck: "Read a sample from the dead-letter store and compare it to the parser's expected shape.",
		Enabled:               true,
		Condition:             condition,
		Fixtures: alerting.Fixtures{
			Positive: []alerting.Subject{{
				Kind: alerting.SubjectSourceHealth, At: fixtureTime,
				NumericVals: map[string]float64{"parse_failure_rate": 0.15},
			}},
			NearMiss: []alerting.Subject{{
				Kind: alerting.SubjectSourceHealth, At: fixtureTime,
				NumericVals: map[string]float64{"parse_failure_rate": 0.0005},
			}},
		},
	}
}

// CorrelationQualityDrop fires when exact joins fall away, which usually means
// identifier propagation broke — for example, Logpush custom fields being
// removed, taking the DataDome bridge with them (FR-072e).
func CorrelationQualityDrop() alerting.Detection {
	condition := func(s alerting.Subject) bool {
		if s.Kind != alerting.SubjectStageHealth {
			return false
		}
		ratio, ok := s.Num("exact_join_ratio")
		if !ok {
			return false
		}
		// Only meaningful once enough flows have formed to make the ratio stable.
		flows, okFlows := s.Num("flows_evaluated")
		return okFlows && flows >= 100 && ratio < 0.80
	}
	return alerting.Detection{
		ID: "pipeline.correlation_quality_drop", Name: "Exact-join rate has fallen",
		Version: "1.0", Severity: alerting.SeverityHigh, Category: "pipeline",
		Hypothesis: "A falling exact-join ratio means records stopped carrying shared " +
			"identifiers. The flows still form heuristically, so nothing looks broken — " +
			"but confidence has quietly dropped.",
		ExpectedResponse:      "Verify Logpush custom fields, nginx $http_cf_ray, and the F5 CF-Ray iRule.",
		RecommendedFirstCheck: "Check whether x-datadome-requestid is still present on Cloudflare records.",
		Enabled:               true,
		Condition:             condition,
		Fixtures: alerting.Fixtures{
			Positive: []alerting.Subject{{
				Kind: alerting.SubjectStageHealth, At: fixtureTime,
				NumericVals: map[string]float64{"exact_join_ratio": 0.42, "flows_evaluated": 5000},
			}},
			NearMiss: []alerting.Subject{
				{ // healthy ratio
					Kind: alerting.SubjectStageHealth, At: fixtureTime,
					NumericVals: map[string]float64{"exact_join_ratio": 0.97, "flows_evaluated": 5000},
				},
				{ // too few flows for the ratio to mean anything yet
					Kind: alerting.SubjectStageHealth, At: fixtureTime,
					NumericVals: map[string]float64{"exact_join_ratio": 0.10, "flows_evaluated": 3},
				},
			},
		},
	}
}

// All returns every built-in detection.
func All() []alerting.Detection {
	return []alerting.Detection{
		SourceSilence(), StageZeroOutput(), ParseFailureSpike(), CorrelationQualityDrop(),
	}
}
