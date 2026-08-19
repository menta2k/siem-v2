package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// FeedRow is one configured ingest endpoint. TokenHash is SHA-256 of the
// token's secret half — the credential itself is never stored.
type FeedRow struct {
	ID             string
	TenantID       string
	Provider       string
	Name           string
	Enabled        bool
	TokenHash      string
	CreatedBy      string
	CreatedAt      time.Time
	UpdatedAt      time.Time
	TokenRotatedAt time.Time
}

// ErrFeedNameTaken reports a duplicate name within a tenant, rendered as a
// conflict rather than an internal error.
var ErrFeedNameTaken = errors.New("postgres: feed name already in use")

// FeedRepo persists feeds.
type FeedRepo struct{ pool *pgxpool.Pool }

func NewFeedRepo(pool *pgxpool.Pool) *FeedRepo { return &FeedRepo{pool: pool} }

const feedColumns = `id, tenant_id, provider, name, enabled, token_hash,
	created_by, created_at, updated_at, token_rotated_at`

func scanFeed(row pgx.Row) (*FeedRow, error) {
	var f FeedRow
	err := row.Scan(&f.ID, &f.TenantID, &f.Provider, &f.Name, &f.Enabled,
		&f.TokenHash, &f.CreatedBy, &f.CreatedAt, &f.UpdatedAt, &f.TokenRotatedAt)
	if err != nil {
		return nil, err
	}
	return &f, nil
}

// Create inserts a new feed.
func (r *FeedRepo) Create(ctx context.Context, f FeedRow) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO feed (id, tenant_id, provider, name, enabled, token_hash, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		f.ID, f.TenantID, f.Provider, f.Name, f.Enabled, f.TokenHash, f.CreatedBy)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return ErrFeedNameTaken
	}
	if err != nil {
		return fmt.Errorf("create feed: %w", err)
	}
	return nil
}

// ListByTenant returns a tenant's feeds for the management screen.
func (r *FeedRepo) ListByTenant(ctx context.Context, tenantID string) ([]FeedRow, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+feedColumns+` FROM feed WHERE tenant_id = $1 ORDER BY provider, name`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list feeds: %w", err)
	}
	defer rows.Close()
	var out []FeedRow
	for rows.Next() {
		f, err := scanFeed(rows)
		if err != nil {
			return nil, fmt.Errorf("scan feed: %w", err)
		}
		out = append(out, *f)
	}
	return out, rows.Err()
}

// ListEnabled returns every enabled feed across tenants — the ingest side's
// working set, refreshed into its cache on an interval.
func (r *FeedRepo) ListEnabled(ctx context.Context) ([]FeedRow, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+feedColumns+` FROM feed WHERE enabled`)
	if err != nil {
		return nil, fmt.Errorf("list enabled feeds: %w", err)
	}
	defer rows.Close()
	var out []FeedRow
	for rows.Next() {
		f, err := scanFeed(rows)
		if err != nil {
			return nil, fmt.Errorf("scan feed: %w", err)
		}
		out = append(out, *f)
	}
	return out, rows.Err()
}

// SetEnabled flips a feed, tenant-scoped like every administrative write.
func (r *FeedRepo) SetEnabled(ctx context.Context, tenantID, feedID string, enabled bool) (bool, error) {
	tag, err := r.pool.Exec(ctx, `
		UPDATE feed SET enabled = $3, updated_at = now()
		WHERE id = $2 AND tenant_id = $1`, tenantID, feedID, enabled)
	if err != nil {
		return false, fmt.Errorf("set feed enabled: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// RotateToken replaces the stored hash. The moment this commits, the old
// credential is dead — v1's semantics, kept deliberately: providers retry
// failed deliveries, so the reconfiguration window loses nothing, and a
// grace period would mean two live credentials with no way to see which one
// a sender is still using.
func (r *FeedRepo) RotateToken(ctx context.Context, tenantID, feedID, tokenHash string) (bool, error) {
	tag, err := r.pool.Exec(ctx, `
		UPDATE feed SET token_hash = $3, token_rotated_at = now(), updated_at = now()
		WHERE id = $2 AND tenant_id = $1`, tenantID, feedID, tokenHash)
	if err != nil {
		return false, fmt.Errorf("rotate feed token: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}
