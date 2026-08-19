package alerting

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"time"
)

// Alert is one firing of a detection.
//
// It carries its own evidence and first step because an alert that requires a
// separate query before anyone can act on it is an alert people learn to skip
// (FR-048).
type Alert struct {
	AlertID          string    `json:"alert_id"`
	DetectionID      string    `json:"detection_id"`
	DetectionVersion string    `json:"detection_version"`
	Tenant           string    `json:"tenant"`
	FiredAt          time.Time `json:"fired_at"`
	Severity         Severity  `json:"severity"`
	Title            string    `json:"title"`

	Evidence              map[string]any `json:"evidence"`
	LinkedFlowIDs         []string       `json:"linked_flow_ids,omitempty"`
	RecommendedFirstCheck string         `json:"recommended_first_check"`
	ExpectedResponse      string         `json:"expected_response"`

	// GroupingKey collapses repeat firings of the same underlying condition.
	GroupingKey     string     `json:"grouping_key"`
	SuppressedUntil *time.Time `json:"suppressed_until,omitempty"`
	OccurrenceCount int        `json:"occurrence_count"`
}

// NewAlert builds an alert from a fired detection and its subject.
func NewAlert(d Detection, s Subject, firedAt time.Time, flowIDs []string) Alert {
	evidence := map[string]any{}
	for k, v := range s.Attributes {
		evidence[k] = v
	}
	for k, v := range s.NumericVals {
		evidence[k] = v
	}

	grouping := groupingKey(d, s)
	return Alert{
		AlertID:               alertID(grouping, firedAt),
		DetectionID:           d.ID,
		DetectionVersion:      d.Version,
		Tenant:                s.Tenant,
		FiredAt:               firedAt,
		Severity:              d.Severity,
		Title:                 d.Name,
		Evidence:              evidence,
		LinkedFlowIDs:         flowIDs,
		RecommendedFirstCheck: d.RecommendedFirstCheck,
		ExpectedResponse:      d.ExpectedResponse,
		GroupingKey:           grouping,
		OccurrenceCount:       1,
	}
}

// groupingKey identifies "the same condition, still happening".
//
// It deliberately excludes time and any rapidly-changing measurement: a source
// that has been silent for 10 minutes and one silent for 11 minutes are the same
// problem, and treating them as two alerts is how a single outage produces a
// hundred pages.
func groupingKey(d Detection, s Subject) string {
	parts := []string{d.ID, d.Version, s.Tenant, string(s.Kind)}
	for _, key := range []string{"source_id", "stage", "rule_id", "client_ip"} {
		if v, ok := s.Str(key); ok {
			parts = append(parts, key+"="+v)
		}
	}
	sum := sha256.Sum256([]byte(joinParts(parts)))
	return hex.EncodeToString(sum[:8])
}

func alertID(grouping string, at time.Time) string {
	sum := sha256.Sum256([]byte(grouping + at.UTC().Format(time.RFC3339Nano)))
	return "alert:" + hex.EncodeToString(sum[:12])
}

func joinParts(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += "|"
		}
		out += p
	}
	return out
}

// Suppressor collapses repeated firings of a persisting condition.
//
// Without this, one stalled stage produces an alert per evaluation cycle, which
// is worse than no alerting at all: the real signal is buried under its own
// repetitions (FR-049).
type Suppressor struct {
	window    time.Duration
	lastFired map[string]time.Time
	counts    map[string]int
}

func NewSuppressor(window time.Duration) *Suppressor {
	if window <= 0 {
		window = 15 * time.Minute
	}
	return &Suppressor{
		window:    window,
		lastFired: map[string]time.Time{},
		counts:    map[string]int{},
	}
}

// Admit reports whether an alert should be delivered now.
//
// A suppressed alert is still counted, so the eventual notification can say how
// many times the condition recurred rather than pretending it happened once.
func (s *Suppressor) Admit(a Alert, now time.Time) (Alert, bool) {
	last, seen := s.lastFired[a.GroupingKey]
	s.counts[a.GroupingKey]++
	a.OccurrenceCount = s.counts[a.GroupingKey]

	if seen && now.Sub(last) < s.window {
		until := last.Add(s.window)
		a.SuppressedUntil = &until
		return a, false
	}

	s.lastFired[a.GroupingKey] = now
	return a, true
}

// Reset clears state for a grouping key, used when a condition resolves so the
// next occurrence alerts immediately rather than being suppressed as a repeat.
func (s *Suppressor) Reset(groupingKey string) {
	delete(s.lastFired, groupingKey)
	delete(s.counts, groupingKey)
}

// SortAlerts orders alerts most severe first, then newest first, which is the
// order an on-call responder wants to read them in.
func SortAlerts(alerts []Alert) {
	rank := map[Severity]int{
		SeverityCritical: 0, SeverityHigh: 1, SeverityMedium: 2, SeverityLow: 3,
	}
	sort.SliceStable(alerts, func(i, j int) bool {
		ri, rj := rank[alerts[i].Severity], rank[alerts[j].Severity]
		if ri != rj {
			return ri < rj
		}
		return alerts[i].FiredAt.After(alerts[j].FiredAt)
	})
}
