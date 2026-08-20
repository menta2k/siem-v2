package victorialogs

import (
	"strings"
	"testing"
	"time"
)

func TestBuildRawExpiryQuery(t *testing.T) {
	cutoff := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	q, err := BuildRawExpiryQuery("default", cutoff)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, want := range []string{
		`tenant="default"`,
		`record_kind="raw"`,
		`_time:<"2026-08-20T12:00:00Z"`,
	} {
		if !strings.Contains(q, want) {
			t.Errorf("query %q missing %q", q, want)
		}
	}
}

func TestBuildRawExpiryQueryRejectsUnsafeTenant(t *testing.T) {
	if _, err := BuildRawExpiryQuery(`de"fault`, time.Now()); err == nil {
		t.Fatal("expected error for unsafe tenant, got nil")
	}
}
