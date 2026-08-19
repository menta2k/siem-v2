package normalize

import (
	"testing"
	"time"

	"github.com/menta2k/siem-v2/backend/internal/normalize/schema"
)

func TestAssessTime(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name      string
		eventTime time.Time
		want      schema.TimeQuality
	}{
		{"same instant", now, schema.TimeQualityOK},
		{"ordinary delivery lag", now.Add(-2 * time.Minute), schema.TimeQualityOK},
		{"hours of lag is still plausible", now.Add(-6 * time.Hour), schema.TimeQualityOK},
		{"slightly ahead is within tolerance", now.Add(-500 * time.Millisecond), schema.TimeQualityOK},
		{"seconds into the future is skew", now.Add(30 * time.Second), schema.TimeQualitySkewed},
		{"days into the future is implausible", now.Add(48 * time.Hour), schema.TimeQualityImplausible},
		{"months in the past is implausible", now.Add(-60 * 24 * time.Hour), schema.TimeQualityImplausible},
		{"zero time is implausible", time.Time{}, schema.TimeQualityImplausible},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := AssessTime(tt.eventTime, now)
			if got != tt.want {
				t.Errorf("want %q, got %q", tt.want, got)
			}
		})
	}
}

// TestApplyTimeQualityNeverAltersTheTimestamp is the point of the whole file: a
// wrong provider clock is a fact about the environment an analyst needs to see.
// Correcting it silently would make two systems' logs agree when they do not.
func TestApplyTimeQualityNeverAltersTheTimestamp(t *testing.T) {
	original := time.Date(2026, 8, 19, 18, 0, 0, 0, time.UTC)
	e := &schema.Event{
		EventTime:  original,
		ReceivedAt: time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC),
	}
	ApplyTimeQuality(e)

	if !e.EventTime.Equal(original) {
		t.Fatalf("event time was modified: %v -> %v", original, e.EventTime)
	}
	if e.TimeQuality != schema.TimeQualitySkewed {
		t.Errorf("six hours into the future should read as skewed, got %q", e.TimeQuality)
	}
	if !e.HasFlag(schema.FlagClockSkew) {
		t.Error("skew must raise a quality flag so it reaches the UI")
	}
	if e.ClockSkewMS == 0 {
		t.Error("the magnitude should be recorded so jitter can be told from a broken clock")
	}
}

func TestApplyTimeQualityFlagsImplausible(t *testing.T) {
	e := &schema.Event{
		EventTime:  time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		ReceivedAt: time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC),
	}
	ApplyTimeQuality(e)
	if !e.HasFlag(schema.FlagImplausibleTime) {
		t.Error("a timestamp months in the future must be flagged implausible")
	}
}

func TestParseErrorCarriesContext(t *testing.T) {
	err := &ParseError{
		Provider: schema.ProviderNginx, Version: "nginx/1.0",
		Reason: "line does not match log_format",
	}
	msg := err.Error()
	for _, want := range []string{"nginx", "nginx/1.0", "log_format"} {
		if !contains(msg, want) {
			t.Errorf("error message should name %q for the dead-letter record to be actionable: %q", want, msg)
		}
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
