package source

import (
	"strings"
	"testing"
	"time"
)

func complete() Source {
	return Source{
		ID: "cf-1", TenantID: "acme", Provider: "cloudflare",
		DeliveryMode: ModePush, ExpectedCadenceSeconds: 900,
		DataClassification: "standard", RetentionPolicyID: "p1",
		ParserVersion: "cloudflare/1.0", DetectionPosture: "pipeline.source_silence",
		FixtureCount: 3,
	}
}

func TestCompleteSourceIsAdmitted(t *testing.T) {
	s, err := Enable(complete())
	if err != nil {
		t.Fatalf("a fully onboarded source should be admitted: %v", err)
	}
	if !s.Enabled {
		t.Error("the source should be enabled")
	}
}

// TestEachMissingPieceIsRefused: every one of these produces a specific quiet
// failure later, which is why onboarding is a gate rather than a checklist.
func TestEachMissingPieceIsRefused(t *testing.T) {
	cases := map[string]func(*Source){
		"no parser":            func(s *Source) { s.ParserVersion = "" },
		"no fixtures":          func(s *Source) { s.FixtureCount = 0 },
		"no cadence":           func(s *Source) { s.ExpectedCadenceSeconds = 0 },
		"no classification":    func(s *Source) { s.DataClassification = "" },
		"no retention":         func(s *Source) { s.RetentionPolicyID = "" },
		"no detection posture": func(s *Source) { s.DetectionPosture = "" },
		"no tenant":            func(s *Source) { s.TenantID = "" },
		"no delivery mode":     func(s *Source) { s.DeliveryMode = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			s := complete()
			mutate(&s)
			enabled, err := Enable(s)
			if err == nil {
				t.Fatalf("%s must prevent onboarding", name)
			}
			if enabled.Enabled {
				t.Fatal("a refused source must not be left enabled")
			}
		})
	}
}

// TestExplicitNoDetectionsIsAcceptable: the requirement is a stated posture, not
// necessarily a detection. "None apply, because X" is a valid answer; silence
// is not.
func TestExplicitNoDetectionsIsAcceptable(t *testing.T) {
	s := complete()
	s.DetectionPosture = "none: this source carries only static asset requests"
	if _, err := Enable(s); err != nil {
		t.Fatalf("an explicit statement that no detections apply is a valid posture: %v", err)
	}
}

func TestErrorNamesEverythingMissing(t *testing.T) {
	s := complete()
	s.ParserVersion = ""
	s.ExpectedCadenceSeconds = 0
	s.DataClassification = ""

	err := Validate(s)
	if err == nil {
		t.Fatal("expected refusal")
	}
	msg := err.Error()
	for _, want := range []string{"parser", "cadence", "classification"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the error should name %q so it can be fixed in one pass: %s", want, msg)
		}
	}
}

func TestHealthDistinguishesNeverFromStopped(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)

	s, _ := Enable(complete())
	if got := Health(s, now); got != "awaiting_first_record" {
		t.Errorf("a source that never delivered is awaiting, not silent: got %q", got)
	}

	s.LastRecordAt = now.Add(-time.Minute)
	if got := Health(s, now); got != "healthy" {
		t.Errorf("recent delivery is healthy, got %q", got)
	}

	s.LastRecordAt = now.Add(-time.Hour)
	if got := Health(s, now); got != "silent" {
		t.Errorf("past its cadence the source is silent, got %q", got)
	}

	s.Enabled = false
	if got := Health(s, now); got != "disabled" {
		t.Errorf("a disabled source is not silent, got %q", got)
	}
}
