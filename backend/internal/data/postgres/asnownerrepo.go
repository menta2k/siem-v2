package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/menta2k/siem-v2/backend/internal/asnowner"
)

// ASNOwnerRepo persists the ASN → owner attribution snapshot.
type ASNOwnerRepo struct{ pool *pgxpool.Pool }

func NewASNOwnerRepo(pool *pgxpool.Pool) *ASNOwnerRepo { return &ASNOwnerRepo{pool: pool} }

// Replace upserts a full snapshot in batches. An empty snapshot is refused:
// it can only mean the download or parse broke, and wiping the table would
// turn a transient upstream failure into bare numbers everywhere (v1 rule).
func (r *ASNOwnerRepo) Replace(ctx context.Context, owners []asnowner.Owner) error {
	if len(owners) == 0 {
		return fmt.Errorf("asnowner: refusing to store an empty snapshot")
	}
	const batchSize = 5000
	for start := 0; start < len(owners); start += batchSize {
		end := min(start+batchSize, len(owners))
		batch := &pgx.Batch{}
		for _, o := range owners[start:end] {
			batch.Queue(`
				INSERT INTO asn_owner (asn, name, country, updated_at)
				VALUES ($1,$2,$3, now())
				ON CONFLICT (asn) DO UPDATE SET
					name = EXCLUDED.name, country = EXCLUDED.country,
					updated_at = EXCLUDED.updated_at`,
				o.ASN, o.Name, o.Country)
		}
		if err := r.pool.SendBatch(ctx, batch).Close(); err != nil {
			return fmt.Errorf("asnowner: store batch at %d: %w", start, err)
		}
	}
	return nil
}

// NamesFor returns the owner names for a set of ASNs. Unknown ASNs are simply
// absent — the caller renders the bare number.
func (r *ASNOwnerRepo) NamesFor(ctx context.Context, asns []int) (map[int]string, error) {
	if len(asns) == 0 {
		return map[int]string{}, nil
	}
	rows, err := r.pool.Query(ctx,
		`SELECT asn, name FROM asn_owner WHERE asn = ANY($1)`, asns)
	if err != nil {
		return nil, fmt.Errorf("asnowner: lookup: %w", err)
	}
	defer rows.Close()
	out := make(map[int]string, len(asns))
	for rows.Next() {
		var asn int
		var name string
		if err := rows.Scan(&asn, &name); err != nil {
			return nil, fmt.Errorf("asnowner: scan: %w", err)
		}
		out[asn] = name
	}
	return out, rows.Err()
}

// Count reports how many attributions are stored — health telemetry for the
// refresh worker.
func (r *ASNOwnerRepo) Count(ctx context.Context) (int, error) {
	var n int
	err := r.pool.QueryRow(ctx, `SELECT count(*) FROM asn_owner`).Scan(&n)
	return n, err
}
