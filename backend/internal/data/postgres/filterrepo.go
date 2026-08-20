package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/menta2k/siem-v2/backend/internal/ingest/filter"
)

// FilterRepo persists per-tenant ingest filter rules.
type FilterRepo struct{ pool *pgxpool.Pool }

func NewFilterRepo(pool *pgxpool.Pool) *FilterRepo { return &FilterRepo{pool: pool} }

// Get returns a tenant's rules. Undecodable stored JSON returns an empty set
// with the error, so callers can fail open while still surfacing the problem.
func (r *FilterRepo) Get(ctx context.Context, tenantID string) ([]filter.Rule, error) {
	var raw []byte
	err := r.pool.QueryRow(ctx,
		`SELECT ingest_filters FROM tenant WHERE id = $1`, tenantID).Scan(&raw)
	if err != nil {
		return nil, fmt.Errorf("load ingest filters: %w", err)
	}
	var rules []filter.Rule
	if err := json.Unmarshal(raw, &rules); err != nil {
		return nil, fmt.Errorf("decode ingest filters: %w", err)
	}
	return rules, nil
}

// Set REPLACES a tenant's rule set (no merge — v1 semantics: what you see in
// the editor is exactly what applies).
func (r *FilterRepo) Set(ctx context.Context, tenantID string, rules []filter.Rule) error {
	if rules == nil {
		rules = []filter.Rule{}
	}
	raw, err := json.Marshal(rules)
	if err != nil {
		return fmt.Errorf("encode ingest filters: %w", err)
	}
	tag, err := r.pool.Exec(ctx,
		`UPDATE tenant SET ingest_filters = $2 WHERE id = $1`, tenantID, raw)
	if err != nil {
		return fmt.Errorf("store ingest filters: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("no such tenant %q", tenantID)
	}
	return nil
}

// All returns every tenant's rules — the ingest cache's refresh source.
func (r *FilterRepo) All(ctx context.Context) (map[string][]filter.Rule, error) {
	rows, err := r.pool.Query(ctx, `SELECT id, ingest_filters FROM tenant`)
	if err != nil {
		return nil, fmt.Errorf("list ingest filters: %w", err)
	}
	defer rows.Close()
	out := map[string][]filter.Rule{}
	for rows.Next() {
		var id string
		var raw []byte
		if err := rows.Scan(&id, &raw); err != nil {
			return nil, fmt.Errorf("scan ingest filters: %w", err)
		}
		var rules []filter.Rule
		if err := json.Unmarshal(raw, &rules); err != nil {
			continue // one tenant's bad JSON must not break the others; it fails open
		}
		if len(rules) > 0 {
			out[id] = rules
		}
	}
	return out, rows.Err()
}
