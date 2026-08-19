package retention

import (
	"context"
	"errors"
	"testing"
	"time"
)

var rnow = time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)

func policy() Policy {
	return Policy{ID: "p1", TenantID: "acme", Name: "default",
		DataCategory: "waf", HotDays: 30, WarmDays: 90, ColdMonths: 12}
}

type fakeHolds struct {
	holds     []Hold
	prevented []string
	err       error
}

func (f *fakeHolds) Open(context.Context, string) ([]Hold, error)             { return f.holds, f.err }
func (f *fakeHolds) Place(context.Context, Hold) error                        { return nil }
func (f *fakeHolds) Release(context.Context, string, string, time.Time) error { return nil }
func (f *fakeHolds) RecordPreventedExpiry(_ context.Context, holdID, ref string, _ time.Time) error {
	f.prevented = append(f.prevented, holdID+":"+ref)
	return nil
}

type fakeArchive struct {
	archived  []string
	preserved []string
}

func (f *fakeArchive) Archive(_ context.Context, p Partition) (string, error) {
	ref := "cold/" + p.Date.Format("2006-01-02")
	f.archived = append(f.archived, ref)
	return ref, nil
}
func (f *fakeArchive) Preserve(_ context.Context, ref string) error {
	f.preserved = append(f.preserved, ref)
	return nil
}

type fakeDeleter struct{ deleted []string }

func (f *fakeDeleter) Delete(_ context.Context, p Partition) error {
	f.deleted = append(f.deleted, p.Date.Format("2006-01-02"))
	return nil
}

func service(h *fakeHolds, a *fakeArchive, d *fakeDeleter) *Service {
	return &Service{Holds: h, Archive: a, Delete: d, Now: func() time.Time { return rnow }}
}

func TestTierAssignment(t *testing.T) {
	p := policy()
	cases := []struct {
		age  time.Duration
		want Tier
	}{
		{1 * 24 * time.Hour, TierHot},
		{29 * 24 * time.Hour, TierHot},
		{60 * 24 * time.Hour, TierWarm},
		{119 * 24 * time.Hour, TierWarm},
		{200 * 24 * time.Hour, TierCold},
		{400 * 24 * time.Hour, TierGone},
	}
	for _, c := range cases {
		got := p.TierFor(rnow.Add(-c.age), rnow)
		if got != c.want {
			t.Errorf("age %v: want %q, got %q", c.age, c.want, got)
		}
	}
}

func TestExpiredPartitionsAreDeleted(t *testing.T) {
	holds, arch, del := &fakeHolds{}, &fakeArchive{}, &fakeDeleter{}
	partitions := []Partition{
		{TenantID: "acme", Date: rnow.Add(-1 * 24 * time.Hour)},   // hot
		{TenantID: "acme", Date: rnow.Add(-200 * 24 * time.Hour)}, // cold
		{TenantID: "acme", Date: rnow.Add(-400 * 24 * time.Hour)}, // expired
	}
	res, err := service(holds, arch, del).Apply(context.Background(), "acme", policy(), partitions)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if res.Archived != 1 || res.Deleted != 1 {
		t.Fatalf("expected 1 archived and 1 deleted, got %+v", res)
	}
	if len(del.deleted) != 1 {
		t.Errorf("only the expired partition should be deleted, got %v", del.deleted)
	}
}

// TestHeldDataSurvivesExpiry is FR-040's core requirement.
func TestHeldDataSurvivesExpiry(t *testing.T) {
	expiredDate := rnow.Add(-400 * 24 * time.Hour)
	holds := &fakeHolds{holds: []Hold{{
		ID: "hold-1", TenantID: "acme", Reason: "litigation",
		PlacedAt: rnow.Add(-10 * 24 * time.Hour),
	}}}
	arch, del := &fakeArchive{}, &fakeDeleter{}

	res, err := service(holds, arch, del).Apply(context.Background(), "acme", policy(),
		[]Partition{{TenantID: "acme", Date: expiredDate}})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}

	if len(del.deleted) != 0 {
		t.Fatal("held data reached its expiry and was DELETED; FR-040 is not satisfied")
	}
	if res.PreventedByHold != 1 {
		t.Errorf("the prevented expiry must be counted, got %+v", res)
	}
	if len(holds.prevented) != 1 {
		t.Error("the prevented expiry must be recorded against the hold as evidence")
	}
	if len(arch.preserved) != 1 {
		t.Error("held data should be copied to immutable storage as defence in depth")
	}
}

// TestUnreadableHoldsAbortTheRun: deleting held evidence is unrecoverable, a
// delayed run is not. Failing closed is the only safe choice.
func TestUnreadableHoldsAbortTheRun(t *testing.T) {
	holds := &fakeHolds{err: errors.New("postgres unreachable")}
	arch, del := &fakeArchive{}, &fakeDeleter{}

	_, err := service(holds, arch, del).Apply(context.Background(), "acme", policy(),
		[]Partition{{TenantID: "acme", Date: rnow.Add(-400 * 24 * time.Hour)}})
	if err == nil {
		t.Fatal("if the hold registry cannot be read, nothing may be expired")
	}
	if len(del.deleted) != 0 {
		t.Fatal("data was deleted without knowing whether it was held")
	}
}

func TestReleasedHoldNoLongerPreserves(t *testing.T) {
	released := rnow.Add(-time.Hour)
	holds := &fakeHolds{holds: []Hold{{
		ID: "hold-1", TenantID: "acme", ReleasedAt: &released,
	}}}
	arch, del := &fakeArchive{}, &fakeDeleter{}

	_, err := service(holds, arch, del).Apply(context.Background(), "acme", policy(),
		[]Partition{{TenantID: "acme", Date: rnow.Add(-400 * 24 * time.Hour)}})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if len(del.deleted) != 1 {
		t.Error("once a hold is released, normal expiry resumes")
	}
}

// TestHoldDoesNotCrossTenants: one tenant's litigation hold must never preserve
// or block another tenant's data.
func TestHoldDoesNotCrossTenants(t *testing.T) {
	holds := &fakeHolds{holds: []Hold{{ID: "h", TenantID: "globex"}}}
	arch, del := &fakeArchive{}, &fakeDeleter{}

	_, err := service(holds, arch, del).Apply(context.Background(), "acme", policy(),
		[]Partition{{TenantID: "acme", Date: rnow.Add(-400 * 24 * time.Hour)}})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if len(del.deleted) != 1 {
		t.Error("a hold belonging to another tenant must not affect this one")
	}
}

func TestHoldWithDateRange(t *testing.T) {
	h := Hold{
		ID: "h", TenantID: "acme",
		ScopeFilter: map[string]any{
			"from": rnow.Add(-500 * 24 * time.Hour).Format(time.RFC3339),
			"to":   rnow.Add(-300 * 24 * time.Hour).Format(time.RFC3339),
		},
	}
	if !h.Covers("acme", rnow.Add(-400*24*time.Hour)) {
		t.Error("a partition inside the range should be covered")
	}
	if h.Covers("acme", rnow.Add(-100*24*time.Hour)) {
		t.Error("a partition outside the range should not be covered")
	}
}

// TestHoldWithNoRangeCoversEverything: a hold placed in haste during an incident
// should over-preserve rather than under-preserve.
func TestHoldWithNoRangeCoversEverything(t *testing.T) {
	h := Hold{ID: "h", TenantID: "acme"}
	for _, age := range []time.Duration{1, 100, 1000} {
		if !h.Covers("acme", rnow.Add(-age*24*time.Hour)) {
			t.Errorf("an unscoped hold must cover everything for the tenant (age %v days)", age)
		}
	}
}

func TestPolicyValidation(t *testing.T) {
	if err := policy().Validate(); err != nil {
		t.Errorf("the default policy should be valid: %v", err)
	}
	bad := policy()
	bad.HotDays = 0
	if err := bad.Validate(); err == nil {
		t.Error("a zero hot window must be rejected")
	}
	incoherent := Policy{Name: "x", HotDays: 30, WarmDays: 400, ColdMonths: 1}
	if err := incoherent.Validate(); err == nil {
		t.Error("a cold window ending before warm does is incoherent and must be rejected")
	}
}
