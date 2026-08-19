package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// SourceRow is a configured feed as shown to an operator.
type SourceRow struct {
	ID                     string     `json:"id"`
	Provider               string     `json:"provider"`
	DeliveryMode           string     `json:"delivery_mode"`
	ExpectedCadenceSeconds int        `json:"expected_cadence_seconds"`
	DataClassification     string     `json:"data_classification"`
	ParserVersion          string     `json:"parser_version"`
	DetectionPosture       string     `json:"detection_posture"`
	Enabled                bool       `json:"enabled"`
	LastRecordAt           *time.Time `json:"last_record_at,omitempty"`
	HealthState            string     `json:"health_state"`
	// CredentialValid distinguishes "the vendor cannot authenticate" from "the
	// vendor is quiet". They look identical on a dashboard and need opposite
	// responses, so they are separate fields rather than one status string.
	CredentialValid bool `json:"credential_valid"`
	SchemaDrift     bool `json:"schema_drift"`
}

// SourceRepo reads and writes source configuration.
type SourceRepo struct{ pool *pgxpool.Pool }

func NewSourceRepo(pool *pgxpool.Pool) *SourceRepo { return &SourceRepo{pool: pool} }

// List returns the tenant's sources.
func (r *SourceRepo) List(ctx context.Context, tenantID string) ([]SourceRow, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, provider, delivery_mode, expected_cadence_seconds,
		       data_classification, parser_version, detection_posture,
		       enabled, last_record_at, health_state
		FROM log_source WHERE tenant_id = $1 ORDER BY provider, id`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []SourceRow
	for rows.Next() {
		var s SourceRow
		if err := rows.Scan(&s.ID, &s.Provider, &s.DeliveryMode, &s.ExpectedCadenceSeconds,
			&s.DataClassification, &s.ParserVersion, &s.DetectionPosture,
			&s.Enabled, &s.LastRecordAt, &s.HealthState); err != nil {
			return nil, err
		}
		s.CredentialValid = true
		out = append(out, s)
	}
	return out, rows.Err()
}

// Upsert creates or updates a source.
func (r *SourceRepo) Upsert(ctx context.Context, tenantID string, s SourceRow) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO log_source (id, tenant_id, provider, delivery_mode,
			expected_cadence_seconds, data_classification, parser_version,
			detection_posture, enabled, last_record_at, health_state)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		ON CONFLICT (id) DO UPDATE SET
			provider = EXCLUDED.provider,
			delivery_mode = EXCLUDED.delivery_mode,
			expected_cadence_seconds = EXCLUDED.expected_cadence_seconds,
			data_classification = EXCLUDED.data_classification,
			parser_version = EXCLUDED.parser_version,
			detection_posture = EXCLUDED.detection_posture,
			enabled = EXCLUDED.enabled`,
		s.ID, tenantID, s.Provider, s.DeliveryMode, s.ExpectedCadenceSeconds,
		s.DataClassification, s.ParserVersion, s.DetectionPosture,
		s.Enabled, s.LastRecordAt, s.HealthState)
	return err
}

// RecordDelivery updates a source's last-seen time.
func (r *SourceRepo) RecordDelivery(ctx context.Context, sourceID string, at time.Time) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE log_source SET last_record_at = $2, health_state = 'healthy' WHERE id = $1`,
		sourceID, at)
	return err
}
