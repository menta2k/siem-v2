package main

import (
	"testing"

	"github.com/menta2k/siem-v2/backend/internal/data/victorialogs"
)

func TestWafReading(t *testing.T) {
	cases := []struct {
		name                                  string
		correlated, blocked, flagged, allowed int
		want                                  string
	}{
		{"too few", 5, 5, 0, 0, "insufficient"},
		{"clear agreement", 100, 90, 0, 10, "ready"},
		{"flagged counts half -> ready", 100, 70, 25, 5, "ready"}, // (70+12.5)/100=0.825
		{"clear disagreement", 100, 5, 0, 95, "false_positive"},
		{"middle -> disputed", 100, 50, 0, 50, "disputed"},
		{"flagged-heavy middle", 100, 30, 40, 30, "disputed"}, // (30+20)/100=0.5
	}
	for _, c := range cases {
		got := wafReading(victorialogs.WafRuleCounts{
			Correlated: c.correlated, F5Blocked: c.blocked, F5Flagged: c.flagged, F5Allowed: c.allowed,
		})
		if got != c.want {
			t.Errorf("%s: reading = %q, want %q", c.name, got, c.want)
		}
	}
}
