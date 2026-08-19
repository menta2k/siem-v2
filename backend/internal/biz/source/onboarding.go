// Package source governs how a log source is admitted into the system.
package source

import (
	"fmt"
	"strings"
	"time"
)

// DeliveryMode is how records reach us.
type DeliveryMode string

const (
	ModePush DeliveryMode = "push"
	ModePull DeliveryMode = "pull"
)

// Source is a configured feed.
type Source struct {
	ID                     string
	TenantID               string
	Provider               string
	DeliveryMode           DeliveryMode
	ExpectedCadenceSeconds int
	DataClassification     string
	RetentionPolicyID      string
	ParserVersion          string
	// DetectionPosture is either the detections that cover this source or an
	// explicit statement that none apply. An empty string is neither.
	DetectionPosture string
	FixtureCount     int
	Enabled          bool
	LastRecordAt     time.Time
}

// ErrNotOnboarded lists everything preventing a source from being admitted.
type ErrNotOnboarded struct {
	SourceID string
	Missing  []string
}

func (e *ErrNotOnboarded) Error() string {
	return fmt.Sprintf("source %q cannot be enabled; missing: %s",
		e.SourceID, strings.Join(e.Missing, ", "))
}

// Validate enforces the definition of "onboarded" from FR-008.
//
// This is a gate rather than a checklist because each missing piece produces a
// specific, quiet failure later: no cadence means silence is undetectable, no
// classification means sensitive data is stored unmasked, no fixtures mean the
// parser is an unverified claim. A half-onboarded source looks like a working
// one until precisely the moment it matters.
func Validate(s Source) error {
	var missing []string

	if strings.TrimSpace(s.ID) == "" {
		missing = append(missing, "id")
	}
	if strings.TrimSpace(s.TenantID) == "" {
		missing = append(missing, "tenant")
	}
	if strings.TrimSpace(s.Provider) == "" {
		missing = append(missing, "provider")
	}
	if s.DeliveryMode != ModePush && s.DeliveryMode != ModePull {
		missing = append(missing, "delivery_mode (push or pull)")
	}
	if strings.TrimSpace(s.ParserVersion) == "" {
		missing = append(missing, "parser")
	}
	if s.FixtureCount == 0 {
		missing = append(missing, "parser fixtures (a parser without them is an unverified claim)")
	}
	if s.ExpectedCadenceSeconds <= 0 {
		missing = append(missing, "expected cadence (without it, silence is undetectable)")
	}
	if strings.TrimSpace(s.DataClassification) == "" {
		missing = append(missing, "data classification (without it, sensitive fields are stored unmasked)")
	}
	if strings.TrimSpace(s.RetentionPolicyID) == "" {
		missing = append(missing, "retention policy")
	}
	if strings.TrimSpace(s.DetectionPosture) == "" {
		missing = append(missing,
			"detection posture (name the detections, or state explicitly that none apply)")
	}

	if len(missing) > 0 {
		return &ErrNotOnboarded{SourceID: s.ID, Missing: missing}
	}
	return nil
}

// Enable admits a source, refusing anything not fully onboarded.
func Enable(s Source) (Source, error) {
	if err := Validate(s); err != nil {
		return s, err
	}
	s.Enabled = true
	return s, nil
}

// Health classifies a source's current state.
//
// The distinction between "never delivered" and "stopped delivering" is
// deliberate: they need different operator responses, and conflating them
// produces alerts people learn to ignore.
func Health(s Source, now time.Time) string {
	if !s.Enabled {
		return "disabled"
	}
	if s.LastRecordAt.IsZero() {
		return "awaiting_first_record"
	}
	cadence := time.Duration(s.ExpectedCadenceSeconds) * time.Second
	if cadence > 0 && now.Sub(s.LastRecordAt) > cadence {
		return "silent"
	}
	return "healthy"
}
