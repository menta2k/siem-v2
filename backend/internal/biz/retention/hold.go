// Package retention enforces expiry, archival and legal hold.
//
// The division of responsibility here follows directly from research.md R7:
// VictoriaLogs has no tiered storage, no immutability and no legal-hold
// primitive, and its deletion rewrites all stored logs. So expiry granularity,
// hold enforcement and archival all live in this service rather than in the
// store, and the store is treated as a hot/warm window only.
package retention

import (
	"context"
	"fmt"
	"time"
)

// Hold preserves data beyond its normal expiry.
type Hold struct {
	ID            string
	TenantID      string
	ScopeFilter   map[string]any
	Reason        string
	PlacedBy      string
	PlacedAt      time.Time
	ReleasedAt    *time.Time
	ReleasedBy    string
	PreservedRefs []string
}

// Open reports whether the hold is still in force.
func (h *Hold) Open() bool { return h.ReleasedAt == nil }

// Covers reports whether the hold applies to a data partition.
//
// Matching is by tenant plus an optional date range. A hold with no range covers
// everything for the tenant, which is the correct default: a hold placed in
// haste during an incident should over-preserve rather than under-preserve.
func (h *Hold) Covers(tenantID string, partitionDate time.Time) bool {
	if !h.Open() || h.TenantID != tenantID {
		return false
	}
	from, hasFrom := dateFrom(h.ScopeFilter, "from")
	to, hasTo := dateFrom(h.ScopeFilter, "to")

	if hasFrom && partitionDate.Before(from) {
		return false
	}
	if hasTo && partitionDate.After(to) {
		return false
	}
	return true
}

func dateFrom(filter map[string]any, key string) (time.Time, bool) {
	raw, ok := filter[key]
	if !ok {
		return time.Time{}, false
	}
	switch v := raw.(type) {
	case time.Time:
		return v, true
	case string:
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return time.Time{}, false
		}
		return t, true
	default:
		return time.Time{}, false
	}
}

// HoldStore persists holds.
type HoldStore interface {
	Open(ctx context.Context, tenantID string) ([]Hold, error)
	Place(ctx context.Context, h Hold) error
	Release(ctx context.Context, id, releasedBy string, at time.Time) error
	RecordPreventedExpiry(ctx context.Context, holdID, ref string, at time.Time) error
}

// Policy describes how long a category is kept in each tier.
type Policy struct {
	ID           string
	TenantID     string
	Name         string
	DataCategory string
	HotDays      int
	WarmDays     int
	ColdMonths   int
}

// Tier names a storage tier.
type Tier string

const (
	TierHot  Tier = "hot"
	TierWarm Tier = "warm"
	TierCold Tier = "cold"
	TierGone Tier = "expired"
)

// TierFor reports which tier a partition belongs in at a given time.
func (p Policy) TierFor(partitionDate, now time.Time) Tier {
	age := now.Sub(partitionDate)
	switch {
	case age < time.Duration(p.HotDays)*24*time.Hour:
		return TierHot
	case age < time.Duration(p.HotDays+p.WarmDays)*24*time.Hour:
		return TierWarm
	case age < time.Duration(p.ColdMonths)*30*24*time.Hour:
		return TierCold
	default:
		return TierGone
	}
}

// Validate rejects a policy that cannot be honoured.
func (p Policy) Validate() error {
	if p.HotDays <= 0 {
		return fmt.Errorf("policy %q: hot_days must be positive", p.Name)
	}
	if p.WarmDays < 0 || p.ColdMonths < 0 {
		return fmt.Errorf("policy %q: tier durations cannot be negative", p.Name)
	}
	// A warm window shorter than hot would make data expire out of warm before
	// it left hot, which is incoherent rather than merely aggressive.
	if p.WarmDays > 0 && p.ColdMonths > 0 &&
		time.Duration(p.HotDays+p.WarmDays)*24*time.Hour > time.Duration(p.ColdMonths)*30*24*time.Hour {
		return fmt.Errorf("policy %q: cold window ends before warm does", p.Name)
	}
	return nil
}
