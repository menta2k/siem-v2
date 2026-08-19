// Package alerting evaluates detections against traffic and against the pipeline
// itself.
package alerting

import (
	"fmt"
	"sort"
	"time"
)

// Severity orders how loudly a detection speaks.
type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Detection is a versioned rule evaluated against traffic or pipeline health.
//
// Detections are defined in repository files and loaded at deploy time, so they
// are reviewed, versioned and diffable like any other code (Constitution III).
type Detection struct {
	ID       string   `yaml:"id" json:"id"`
	Name     string   `yaml:"name" json:"name"`
	Version  string   `yaml:"version" json:"version"`
	Severity Severity `yaml:"severity" json:"severity"`
	Category string   `yaml:"category" json:"category"`
	// Hypothesis states what this detection believes and why. A detection without
	// one cannot be reviewed meaningfully six months later.
	Hypothesis string `yaml:"hypothesis" json:"hypothesis"`
	// MITREAttack maps the detection to technique ids where applicable.
	MITREAttack []string `yaml:"mitre_attack" json:"mitre_attack,omitempty"`
	// ExpectedResponse tells the responder what to do, so an alert arrives with
	// its own first step rather than sending them hunting.
	ExpectedResponse string `yaml:"expected_response" json:"expected_response"`
	// RecommendedFirstCheck is surfaced directly on the alert (FR-048).
	RecommendedFirstCheck string `yaml:"recommended_first_check" json:"recommended_first_check"`
	Enabled               bool   `yaml:"enabled" json:"enabled"`

	// Condition is the rule's predicate, evaluated against a Subject.
	Condition Condition `yaml:"-" json:"-"`
	// Fixtures are the proof the detection works. Both kinds are mandatory.
	Fixtures Fixtures `yaml:"-" json:"-"`
}

// Condition decides whether a subject matches.
type Condition func(Subject) bool

// Subject is whatever a detection examines: a flow summary, a source's health,
// a stage's throughput. Keeping it one type lets traffic detections and pipeline
// detections share the engine, which matters because Principle IV insists the
// second kind is not an afterthought.
type Subject struct {
	Kind        SubjectKind
	Tenant      string
	At          time.Time
	Attributes  map[string]any
	NumericVals map[string]float64
}

type SubjectKind string

const (
	SubjectFlow         SubjectKind = "flow"
	SubjectSourceHealth SubjectKind = "source_health"
	SubjectStageHealth  SubjectKind = "stage_health"
)

// Fixtures are the evidence a detection behaves as claimed.
//
// Both a positive and a near-miss are required. The near-miss is the one people
// skip and the one that catches the real problem: a rule that fires on
// everything passes any positive test you can write.
type Fixtures struct {
	Positive []Subject
	NearMiss []Subject
}

// Num reads a numeric attribute.
func (s Subject) Num(key string) (float64, bool) {
	v, ok := s.NumericVals[key]
	return v, ok
}

// Str reads a string attribute.
func (s Subject) Str(key string) (string, bool) {
	v, ok := s.Attributes[key]
	if !ok {
		return "", false
	}
	str, ok := v.(string)
	return str, ok
}

// ValidateFixtures is the activation gate.
//
// A detection that has not proven itself against a positive AND a near-miss
// cannot be enabled. This is a hard refusal rather than a warning because the
// dominant SIEM failure mode is not a noisy rule — it is a rule that silently
// stopped firing and nobody noticed (Constitution III, FR-051).
func ValidateFixtures(d Detection) error {
	if d.Condition == nil {
		return fmt.Errorf("detection %q has no condition", d.ID)
	}
	if len(d.Fixtures.Positive) == 0 {
		return fmt.Errorf("detection %q has no positive fixture: "+
			"an untested detection is an unverified claim about safety", d.ID)
	}
	if len(d.Fixtures.NearMiss) == 0 {
		return fmt.Errorf("detection %q has no near-miss fixture: "+
			"a rule that fires on everything passes any positive test", d.ID)
	}
	if d.Hypothesis == "" {
		return fmt.Errorf("detection %q has no stated hypothesis", d.ID)
	}

	for i, subject := range d.Fixtures.Positive {
		if !d.Condition(subject) {
			return fmt.Errorf("detection %q does not fire on its own positive fixture %d", d.ID, i)
		}
	}
	for i, subject := range d.Fixtures.NearMiss {
		if d.Condition(subject) {
			return fmt.Errorf("detection %q fires on its near-miss fixture %d, "+
				"so it does not discriminate", d.ID, i)
		}
	}
	return nil
}

// Registry holds the activated detections.
type Registry struct {
	detections map[string]Detection
}

func NewRegistry() *Registry {
	return &Registry{detections: map[string]Detection{}}
}

// Activate registers a detection, refusing any that has not passed its fixtures.
func (r *Registry) Activate(d Detection) error {
	if err := ValidateFixtures(d); err != nil {
		return fmt.Errorf("refusing to activate: %w", err)
	}
	r.detections[d.ID] = d
	return nil
}

// Evaluate runs every enabled detection against a subject.
func (r *Registry) Evaluate(s Subject) []Detection {
	var fired []Detection
	for _, d := range r.detections {
		if !d.Enabled {
			continue
		}
		if d.Condition(s) {
			fired = append(fired, d)
		}
	}
	sort.Slice(fired, func(i, j int) bool { return fired[i].ID < fired[j].ID })
	return fired
}

// All returns the registered detections, ordered.
func (r *Registry) All() []Detection {
	out := make([]Detection, 0, len(r.detections))
	for _, d := range r.detections {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
