package retention

import (
	"context"
	"fmt"
	"time"
)

// Partition is one day's data for a tenant, the unit VictoriaLogs actually
// expires. Record-level deletion exists but rewrites all stored logs, so it is a
// scheduled operation rather than a per-record TTL (R7).
type Partition struct {
	TenantID  string
	Date      time.Time
	Tier      Tier
	SizeBytes int64
}

// Archiver moves partitions to cold storage.
type Archiver interface {
	Archive(ctx context.Context, p Partition) (ref string, err error)
	Preserve(ctx context.Context, ref string) error
}

// Deleter removes a partition from a hot or warm store.
type Deleter interface {
	Delete(ctx context.Context, p Partition) error
}

// Auditor records retention decisions.
type Auditor interface {
	Record(ctx context.Context, tenantID, action, target, outcome string, detail map[string]any) error
}

// Service applies retention policy.
type Service struct {
	Holds   HoldStore
	Archive Archiver
	Delete  Deleter
	Audit   Auditor
	Now     func() time.Time
}

// Result summarizes one retention run.
type Result struct {
	Archived        int
	Deleted         int
	PreventedByHold int
	Errors          []error
}

// Apply runs retention over a set of partitions.
//
// The ordering is the safety property: holds are checked BEFORE anything is
// deleted, and a held partition is preserved and recorded rather than removed.
// The hold registry is the primary enforcement — it does not depend on the
// object store honouring Object Lock, so a store that silently failed to enforce
// would degrade tamper-resistance without breaking hold correctness.
func (s *Service) Apply(ctx context.Context, tenantID string, policy Policy, partitions []Partition) (Result, error) {
	var result Result
	now := s.now()

	holds, err := s.Holds.Open(ctx, tenantID)
	if err != nil {
		// Without knowing the holds we cannot safely delete anything. Failing the
		// whole run is correct: deleting held evidence is unrecoverable, while a
		// delayed run is not.
		return result, fmt.Errorf("cannot read legal holds; refusing to expire anything: %w", err)
	}

	for _, p := range partitions {
		tier := policy.TierFor(p.Date, now)

		if held, hold := heldBy(holds, tenantID, p.Date); held {
			if tier == TierGone {
				// The case FR-040 exists for: data reached its expiry while a hold
				// was open. It is preserved, and the prevented expiry is recorded.
				result.PreventedByHold++
				if err := s.preserve(ctx, hold, p); err != nil {
					result.Errors = append(result.Errors, err)
				}
			}
			continue
		}

		switch tier {
		case TierCold:
			ref, err := s.Archive.Archive(ctx, p)
			if err != nil {
				result.Errors = append(result.Errors, fmt.Errorf("archive %s: %w", p.Date.Format("2006-01-02"), err))
				continue
			}
			result.Archived++
			s.audit(ctx, tenantID, "retention.archive", ref, "ok", map[string]any{
				"partition": p.Date.Format("2006-01-02"),
			})
		case TierGone:
			if err := s.Delete.Delete(ctx, p); err != nil {
				result.Errors = append(result.Errors, fmt.Errorf("delete %s: %w", p.Date.Format("2006-01-02"), err))
				continue
			}
			result.Deleted++
			s.audit(ctx, tenantID, "retention.expire", p.Date.Format("2006-01-02"), "ok", nil)
		}
	}
	return result, nil
}

// preserve copies held data to immutable storage and records that expiry was
// prevented, which FR-040 requires as evidence in its own right.
func (s *Service) preserve(ctx context.Context, hold Hold, p Partition) error {
	ref, err := s.Archive.Archive(ctx, p)
	if err != nil {
		return fmt.Errorf("preserve held partition %s: %w", p.Date.Format("2006-01-02"), err)
	}
	if err := s.Archive.Preserve(ctx, ref); err != nil {
		return fmt.Errorf("apply hold protection to %s: %w", ref, err)
	}
	if err := s.Holds.RecordPreventedExpiry(ctx, hold.ID, ref, s.now()); err != nil {
		return fmt.Errorf("record prevented expiry: %w", err)
	}
	s.audit(ctx, hold.TenantID, "retention.expiry_prevented", ref, "held", map[string]any{
		"hold_id":   hold.ID,
		"reason":    hold.Reason,
		"partition": p.Date.Format("2006-01-02"),
	})
	return nil
}

func heldBy(holds []Hold, tenantID string, date time.Time) (bool, Hold) {
	for _, h := range holds {
		if h.Covers(tenantID, date) {
			return true, h
		}
	}
	return false, Hold{}
}

func (s *Service) audit(ctx context.Context, tenantID, action, target, outcome string, detail map[string]any) {
	if s.Audit == nil {
		return
	}
	_ = s.Audit.Record(ctx, tenantID, action, target, outcome, detail)
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now().UTC()
}
