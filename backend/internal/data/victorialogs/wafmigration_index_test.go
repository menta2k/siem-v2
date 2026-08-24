package victorialogs

import (
	"testing"

	"github.com/menta2k/siem-v2/backend/internal/biz/flow"
	"github.com/menta2k/siem-v2/backend/internal/normalize/schema"
)

func TestWafVerdict(t *testing.T) {
	cases := map[schema.Action]string{
		schema.ActionBlocked:         "blocked",
		schema.ActionChallengeFailed: "blocked",
		schema.ActionRateLimited:     "blocked",
		schema.ActionLogged:          "monitored",
		schema.ActionAllowed:         "allowed",
		schema.ActionChallenged:      "allowed",
		"":                           "",
	}
	for a, want := range cases {
		if got := wafVerdict(a); got != want {
			t.Errorf("wafVerdict(%q) = %q, want %q", a, got, want)
		}
	}
}

func TestF5ViolationTokens(t *testing.T) {
	e := &schema.Event{Verdict: schema.Verdict{ReasonRaw: map[string]any{
		"violations": "Illegal query string length,Illegal URL length,Illegal query string length",
	}}}
	got := f5ViolationTokens(e)
	if len(got) != 2 || got[0] != "illegal_query_string_length" || got[1] != "illegal_url_length" {
		t.Fatalf("tokens = %v", got)
	}
	if f5ViolationTokens(&schema.Event{Verdict: schema.Verdict{ReasonRaw: map[string]any{"violations": "N/A"}}}) != nil {
		t.Fatal("N/A must yield no tokens")
	}
}

func TestCfMatchedRuleIDs(t *testing.T) {
	// array of all matched rules (incl. log-mode) preferred
	e := &schema.Event{Verdict: schema.Verdict{
		RuleID:    "deciding",
		ReasonRaw: map[string]any{"SecurityRuleIDs": []string{"r1", "r2", "deciding"}},
	}}
	got := cfMatchedRuleIDs(e)
	if len(got) != 3 || got[0] != "r1" {
		t.Fatalf("matched rules = %v", got)
	}
	// []any after a JSON round-trip
	e2 := &schema.Event{Verdict: schema.Verdict{ReasonRaw: map[string]any{"SecurityRuleIDs": []any{"a", "b"}}}}
	if got := cfMatchedRuleIDs(e2); len(got) != 2 || got[1] != "b" {
		t.Fatalf("any slice = %v", got)
	}
	// fallback to deciding rule when no array
	e3 := &schema.Event{Verdict: schema.Verdict{RuleID: "only"}}
	if got := cfMatchedRuleIDs(e3); len(got) != 1 || got[0] != "only" {
		t.Fatalf("fallback = %v", got)
	}
}

func TestWafIndexFields(t *testing.T) {
	f := &flow.Flow{Events: []schema.Event{
		{Provider: schema.ProviderCloudflare, Layer: schema.LayerEdge, Verdict: schema.Verdict{
			Action: schema.ActionLogged, RuleID: "cf1",
			ReasonRaw: map[string]any{"SecurityRuleIDs": []string{"cf1", "cf2"}},
		}},
		{Provider: schema.ProviderF5ASM, Layer: schema.LayerAppFirewall, Verdict: schema.Verdict{
			Action: schema.ActionBlocked, ReasonRaw: map[string]any{"violations": "Illegal URL length"},
		}},
	}}
	f5v, cfv, f5viol, cfrules := wafIndexFields(f)
	if f5v != "blocked" || cfv != "monitored" {
		t.Fatalf("verdicts f5=%q cf=%q", f5v, cfv)
	}
	if f5viol != "illegal_url_length" {
		t.Fatalf("violations = %q", f5viol)
	}
	if cfrules != "cf1 cf2" {
		t.Fatalf("matched rules = %q", cfrules)
	}
}
