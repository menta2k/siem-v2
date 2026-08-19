package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// AuditEntry is one recorded action.
type AuditEntry struct {
	TenantID    string
	PrincipalID string
	Action      string
	Scope       string
	TargetRef   string
	OccurredAt  time.Time
	Outcome     string
	Detail      map[string]any
}

// AuditRepo appends to the audit trail.
//
// There is deliberately no Update or Delete method. The absence is the point:
// the database rejects mutation anyway, but a repository that offers no way to
// try makes the intent obvious at the call site.
type AuditRepo struct{ pool *pgxpool.Pool }

func NewAuditRepo(pool *pgxpool.Pool) *AuditRepo { return &AuditRepo{pool: pool} }

// Append records an action. Failures are returned rather than swallowed: an
// action that could not be audited is one the system should not claim happened.
func (r *AuditRepo) Append(ctx context.Context, e AuditEntry) error {
	detail, err := json.Marshal(e.Detail)
	if err != nil {
		return fmt.Errorf("encode audit detail: %w", err)
	}
	occurred := e.OccurredAt
	if occurred.IsZero() {
		occurred = time.Now().UTC()
	}
	_, err = r.pool.Exec(ctx, `
		INSERT INTO audit_record (tenant_id, principal_id, action, scope, target_ref, occurred_at, outcome, detail)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		e.TenantID, e.PrincipalID, e.Action, e.Scope, nullable(e.TargetRef), occurred, e.Outcome, detail)
	if err != nil {
		return fmt.Errorf("append audit record: %w", err)
	}
	return nil
}

// List returns audit entries for a tenant, newest first.
func (r *AuditRepo) List(ctx context.Context, tenantID string, limit int) ([]AuditEntry, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := r.pool.Query(ctx, `
		SELECT tenant_id, principal_id, action, scope, COALESCE(target_ref,''), occurred_at, outcome, detail
		FROM audit_record WHERE tenant_id = $1 ORDER BY occurred_at DESC LIMIT $2`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var detail []byte
		if err := rows.Scan(&e.TenantID, &e.PrincipalID, &e.Action, &e.Scope,
			&e.TargetRef, &e.OccurredAt, &e.Outcome, &detail); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(detail, &e.Detail)
		out = append(out, e)
	}
	return out, rows.Err()
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}
