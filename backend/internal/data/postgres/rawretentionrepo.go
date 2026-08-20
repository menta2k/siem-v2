package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// RawRetentionRepo reads and writes the per-tenant retention window (in days)
// for raw provider evidence. The value lives on the tenant row because it is a
// data-governance decision, alongside ingest_filters.
type RawRetentionRepo struct{ pool *pgxpool.Pool }

func NewRawRetentionRepo(pool *pgxpool.Pool) *RawRetentionRepo {
	return &RawRetentionRepo{pool: pool}
}

// Bounds constrain the configurable window so a fat-fingered value cannot
// either disable expiry (0) or exceed what the instance can hold.
const (
	RawRetentionMinDays = 1
	RawRetentionMaxDays = 365
)

// Get returns the tenant's raw retention window in days.
func (r *RawRetentionRepo) Get(ctx context.Context, tenantID string) (int, error) {
	var days int
	err := r.pool.QueryRow(ctx,
		`SELECT raw_retention_days FROM tenant WHERE id = $1`, tenantID).Scan(&days)
	if err != nil {
		return 0, fmt.Errorf("load raw retention: %w", err)
	}
	return days, nil
}

// Set replaces the tenant's raw retention window after validating bounds.
func (r *RawRetentionRepo) Set(ctx context.Context, tenantID string, days int) error {
	if days < RawRetentionMinDays || days > RawRetentionMaxDays {
		return fmt.Errorf("raw retention must be between %d and %d days, got %d",
			RawRetentionMinDays, RawRetentionMaxDays, days)
	}
	tag, err := r.pool.Exec(ctx,
		`UPDATE tenant SET raw_retention_days = $2 WHERE id = $1`, tenantID, days)
	if err != nil {
		return fmt.Errorf("store raw retention: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("no such tenant %q", tenantID)
	}
	return nil
}

// All returns every tenant's raw retention window, for the scheduled expiry
// pass that must enforce each tenant's setting independently.
func (r *RawRetentionRepo) All(ctx context.Context) (map[string]int, error) {
	rows, err := r.pool.Query(ctx, `SELECT id, raw_retention_days FROM tenant`)
	if err != nil {
		return nil, fmt.Errorf("list raw retention: %w", err)
	}
	defer rows.Close()
	out := make(map[string]int)
	for rows.Next() {
		var id string
		var days int
		if err := rows.Scan(&id, &days); err != nil {
			return nil, fmt.Errorf("scan raw retention: %w", err)
		}
		out[id] = days
	}
	return out, rows.Err()
}
