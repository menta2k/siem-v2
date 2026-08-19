// Package verdict analyses decisions across the layers of a request flow.
package verdict

import (
	"fmt"

	"github.com/menta2k/siem-v2/backend/internal/normalize/schema"
)

// ConflictKind names a disagreement worth an analyst's attention.
type ConflictKind string

const (
	// ScoreConflict: a layer scored the request as hostile but allowed it. This
	// is the single most useful cross-provider signal the system produces —
	// "DataDome allowed this and F5 blocked it" is invisible to any one console.
	ScoreConflict ConflictKind = "score_conflict"
	// LayerDisagreement: two layers reached opposite decisions.
	LayerDisagreement ConflictKind = "layer_disagreement"
	// UnmappedVerdict: a provider reported something we do not recognize.
	UnmappedVerdict ConflictKind = "unmapped_verdict"
	// BlockedAfterAllow: a later layer blocked what an earlier one allowed, which
	// means the earlier layer's judgement was wrong or its rules are stale.
	BlockedAfterAllow ConflictKind = "blocked_after_allow"
)

// Conflict describes one disagreement.
type Conflict struct {
	Kind        ConflictKind   `json:"kind"`
	Description string         `json:"description"`
	Layers      []schema.Layer `json:"layers,omitempty"`
	Severity    string         `json:"severity"`
}

// botScoreSuspicious is the DataDome score below which traffic is considered
// likely automated. Scores run 0 (certainly a bot) to 100 (certainly human), so
// a LOW score on an ALLOWED request is the interesting case.
const botScoreSuspicious = 20

// Analyse reports the disagreements across a flow's ordered events.
//
// The point is not to second-guess any provider but to surface where they
// disagreed, because that is precisely what a single-console view cannot show
// and what a false-positive or evasion investigation starts from.
func Analyse(events []schema.Event) []Conflict {
	var conflicts []Conflict

	conflicts = append(conflicts, scoreConflicts(events)...)
	conflicts = append(conflicts, disagreements(events)...)
	conflicts = append(conflicts, unmapped(events)...)

	return conflicts
}

// scoreConflicts finds layers that scored a request as hostile yet allowed it.
func scoreConflicts(events []schema.Event) []Conflict {
	var out []Conflict
	for _, e := range events {
		if e.Verdict.Action != schema.ActionAllowed {
			continue
		}
		// A bot score is not a WAF threat rating and must not be treated as one:
		// a high threat rating on an allowed request is only a severity hint,
		// while a bot score contradicting an allow is a genuine conflict.
		if e.Bot != nil && e.Bot.DataDomeScore != nil && *e.Bot.DataDomeScore < botScoreSuspicious {
			out = append(out, Conflict{
				Kind: ScoreConflict,
				Description: fmt.Sprintf(
					"%s allowed the request while scoring it %.0f, which indicates automation",
					e.Layer, *e.Bot.DataDomeScore),
				Layers: []schema.Layer{e.Layer}, Severity: "medium",
			})
			continue
		}
		if e.Bot != nil && e.Bot.CFBotScore != nil && *e.Bot.CFBotScore < botScoreSuspicious {
			out = append(out, Conflict{
				Kind: ScoreConflict,
				Description: fmt.Sprintf(
					"%s allowed the request with a bot score of %d", e.Layer, *e.Bot.CFBotScore),
				Layers: []schema.Layer{e.Layer}, Severity: "low",
			})
		}
	}
	return out
}

// disagreements finds layers that reached opposite conclusions.
func disagreements(events []schema.Event) []Conflict {
	var allowed, blocked []schema.Layer
	for _, e := range events {
		switch e.Verdict.Action {
		case schema.ActionAllowed:
			allowed = append(allowed, e.Layer)
		case schema.ActionBlocked, schema.ActionChallengeFailed:
			blocked = append(blocked, e.Layer)
		}
	}
	if len(allowed) == 0 || len(blocked) == 0 {
		return nil
	}

	out := []Conflict{{
		Kind: LayerDisagreement,
		Description: fmt.Sprintf(
			"%v allowed the request while %v blocked it", allowed, blocked),
		Layers:   append(append([]schema.Layer{}, allowed...), blocked...),
		Severity: "medium",
	}}

	// Order matters here: a block AFTER an allow means the earlier layer let
	// through something the later one caught, which is a gap in the outer layer.
	if firstIndex(events, blocked[0]) > firstIndex(events, allowed[0]) {
		out = append(out, Conflict{
			Kind: BlockedAfterAllow,
			Description: fmt.Sprintf(
				"%s allowed what %s later blocked; the outer layer's rules may be stale",
				allowed[0], blocked[0]),
			Layers: []schema.Layer{allowed[0], blocked[0]}, Severity: "high",
		})
	}
	return out
}

func unmapped(events []schema.Event) []Conflict {
	var out []Conflict
	for _, e := range events {
		if e.Verdict.Mapped {
			continue
		}
		out = append(out, Conflict{
			Kind: UnmappedVerdict,
			Description: fmt.Sprintf(
				"%s reported a decision this system does not recognize; the raw value is preserved",
				e.Provider),
			Layers: []schema.Layer{e.Layer}, Severity: "low",
		})
	}
	return out
}

func firstIndex(events []schema.Event, layer schema.Layer) int {
	for i, e := range events {
		if e.Layer == layer {
			return i
		}
	}
	return -1
}
