package alerting

import (
	"testing"
	"time"
)

var abase = time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)

func testDetection() Detection {
	return Detection{
		ID: "pipeline.test", Name: "Test detection", Version: "1.0",
		Severity: SeverityHigh, Hypothesis: "testing",
		ExpectedResponse: "do the thing", RecommendedFirstCheck: "check the thing",
		Enabled: true,
		// Discriminating on purpose: a condition returning true for everything is
		// refused by the activation gate, which is the whole point of the near-miss
		// requirement.
		Condition: func(s Subject) bool { return s.Kind == SubjectFlow || s.Kind == SubjectSourceHealth },
		Fixtures: Fixtures{
			Positive: []Subject{{Kind: SubjectFlow}},
			NearMiss: []Subject{{Kind: SubjectStageHealth}},
		},
	}
}

func TestAlertCarriesEvidenceAndFirstStep(t *testing.T) {
	s := Subject{
		Kind: SubjectSourceHealth, Tenant: "acme", At: abase,
		Attributes:  map[string]any{"source_id": "cf-1"},
		NumericVals: map[string]float64{"seconds_since_last_record": 900},
	}
	a := NewAlert(testDetection(), s, abase, []string{"flow:1", "flow:2"})

	if a.RecommendedFirstCheck == "" || a.ExpectedResponse == "" {
		t.Error("an alert without a first step sends the responder hunting")
	}
	if a.DetectionVersion != "1.0" {
		t.Error("the version that fired must be recorded")
	}
	if a.Evidence["source_id"] != "cf-1" || a.Evidence["seconds_since_last_record"] != 900.0 {
		t.Errorf("evidence must be carried on the alert: %v", a.Evidence)
	}
	if len(a.LinkedFlowIDs) != 2 {
		t.Error("linked flows let an investigation start without a separate query")
	}
}

// TestPersistingConditionIsSuppressed is what stops one outage producing a
// hundred pages.
func TestPersistingConditionIsSuppressed(t *testing.T) {
	sup := NewSuppressor(15 * time.Minute)
	s := Subject{
		Kind: SubjectSourceHealth, Tenant: "acme",
		Attributes: map[string]any{"source_id": "cf-1"},
	}

	first, ok := sup.Admit(NewAlert(testDetection(), s, abase, nil), abase)
	if !ok {
		t.Fatal("the first occurrence must be delivered")
	}
	if first.OccurrenceCount != 1 {
		t.Errorf("first occurrence count: got %d", first.OccurrenceCount)
	}

	second, ok := sup.Admit(NewAlert(testDetection(), s, abase.Add(time.Minute), nil), abase.Add(time.Minute))
	if ok {
		t.Fatal("the same condition one minute later must be suppressed")
	}
	if second.SuppressedUntil == nil {
		t.Error("a suppressed alert should say until when")
	}
	if second.OccurrenceCount != 2 {
		t.Errorf("a suppressed occurrence must still be counted, got %d", second.OccurrenceCount)
	}

	later, ok := sup.Admit(NewAlert(testDetection(), s, abase.Add(20*time.Minute), nil), abase.Add(20*time.Minute))
	if !ok {
		t.Fatal("past the suppression window the condition must alert again")
	}
	if later.OccurrenceCount != 3 {
		t.Errorf("occurrence count should keep accumulating, got %d", later.OccurrenceCount)
	}
}

// TestDifferentSubjectsAreNotGroupedTogether: two silent sources are two
// problems, and suppressing the second would hide a real outage.
func TestDifferentSubjectsAreNotGroupedTogether(t *testing.T) {
	sup := NewSuppressor(15 * time.Minute)
	sourceA := Subject{Kind: SubjectSourceHealth, Tenant: "acme", Attributes: map[string]any{"source_id": "cf-1"}}
	sourceB := Subject{Kind: SubjectSourceHealth, Tenant: "acme", Attributes: map[string]any{"source_id": "f5-1"}}

	if _, ok := sup.Admit(NewAlert(testDetection(), sourceA, abase, nil), abase); !ok {
		t.Fatal("first source should alert")
	}
	if _, ok := sup.Admit(NewAlert(testDetection(), sourceB, abase, nil), abase); !ok {
		t.Fatal("a different source is a different problem and must alert separately")
	}
}

// TestGroupingIgnoresChangingMeasurements: 10 minutes silent and 11 minutes
// silent are the same problem.
func TestGroupingIgnoresChangingMeasurements(t *testing.T) {
	s1 := Subject{
		Kind: SubjectSourceHealth, Tenant: "acme",
		Attributes:  map[string]any{"source_id": "cf-1"},
		NumericVals: map[string]float64{"seconds_since_last_record": 600},
	}
	s2 := Subject{
		Kind: SubjectSourceHealth, Tenant: "acme",
		Attributes:  map[string]any{"source_id": "cf-1"},
		NumericVals: map[string]float64{"seconds_since_last_record": 660},
	}
	a1 := NewAlert(testDetection(), s1, abase, nil)
	a2 := NewAlert(testDetection(), s2, abase.Add(time.Minute), nil)

	if a1.GroupingKey != a2.GroupingKey {
		t.Fatal("a still-worsening measurement is the same condition, not a new alert")
	}
}

func TestResetAllowsImmediateRealert(t *testing.T) {
	sup := NewSuppressor(time.Hour)
	s := Subject{Kind: SubjectSourceHealth, Tenant: "acme", Attributes: map[string]any{"source_id": "cf-1"}}

	a := NewAlert(testDetection(), s, abase, nil)
	sup.Admit(a, abase)
	if _, ok := sup.Admit(a, abase.Add(time.Minute)); ok {
		t.Fatal("should be suppressed")
	}
	sup.Reset(a.GroupingKey)
	if _, ok := sup.Admit(a, abase.Add(2*time.Minute)); !ok {
		t.Fatal("after the condition resolves, a recurrence must alert immediately")
	}
}

func TestTenantIsolationInGrouping(t *testing.T) {
	acme := Subject{Kind: SubjectSourceHealth, Tenant: "acme", Attributes: map[string]any{"source_id": "cf-1"}}
	globex := Subject{Kind: SubjectSourceHealth, Tenant: "globex", Attributes: map[string]any{"source_id": "cf-1"}}

	a := NewAlert(testDetection(), acme, abase, nil)
	b := NewAlert(testDetection(), globex, abase, nil)
	if a.GroupingKey == b.GroupingKey {
		t.Fatal("two tenants' alerts must never collapse into one; suppressing across " +
			"tenants would hide one customer's outage behind another's")
	}
}

func TestSortAlertsPutsCriticalFirst(t *testing.T) {
	alerts := []Alert{
		{Severity: SeverityLow, FiredAt: abase.Add(time.Hour)},
		{Severity: SeverityCritical, FiredAt: abase},
		{Severity: SeverityMedium, FiredAt: abase.Add(2 * time.Hour)},
		{Severity: SeverityHigh, FiredAt: abase},
	}
	SortAlerts(alerts)
	want := []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow}
	for i, s := range want {
		if alerts[i].Severity != s {
			t.Fatalf("position %d: want %q, got %q", i, s, alerts[i].Severity)
		}
	}
}

func TestEvaluateOnlyRunsEnabledDetections(t *testing.T) {
	r := NewRegistry()
	d := testDetection()
	if err := r.Activate(d); err != nil {
		t.Fatalf("activate: %v", err)
	}
	if fired := r.Evaluate(Subject{Kind: SubjectFlow}); len(fired) != 1 {
		t.Fatalf("enabled detection should fire, got %d", len(fired))
	}
}
