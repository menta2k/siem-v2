package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/menta2k/siem-v2/backend/internal/alerting"
)

// AlertRepo stores and retrieves alerts.
type AlertRepo struct{ pool *pgxpool.Pool }

func NewAlertRepo(pool *pgxpool.Pool) *AlertRepo { return &AlertRepo{pool: pool} }

// Save records a fired alert.
func (r *AlertRepo) Save(ctx context.Context, a alerting.Alert, deliveryState string) error {
	evidence, err := json.Marshal(a.Evidence)
	if err != nil {
		return fmt.Errorf("encode evidence: %w", err)
	}
	_, err = r.pool.Exec(ctx, `
		INSERT INTO alert (id, tenant_id, detection_id, detection_version, fired_at,
			severity, title, evidence, linked_flow_ids, grouping_key, occurrence_count, delivery_state)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		ON CONFLICT (id) DO UPDATE SET
			occurrence_count = EXCLUDED.occurrence_count,
			delivery_state = EXCLUDED.delivery_state`,
		a.AlertID, a.Tenant, a.DetectionID, a.DetectionVersion, a.FiredAt,
		string(a.Severity), a.Title, evidence, a.LinkedFlowIDs, a.GroupingKey,
		a.OccurrenceCount, deliveryState)
	return err
}

// AlertRow is an alert as returned to the UI.
type AlertRow struct {
	AlertID          string         `json:"alert_id"`
	DetectionID      string         `json:"detection_id"`
	DetectionVersion string         `json:"detection_version"`
	FiredAt          time.Time      `json:"fired_at"`
	Severity         string         `json:"severity"`
	Title            string         `json:"title"`
	Evidence         map[string]any `json:"evidence"`
	LinkedFlowIDs    []string       `json:"linked_flow_ids"`
	OccurrenceCount  int            `json:"occurrence_count"`
	DeliveryState    string         `json:"delivery_state"`
	AcknowledgedBy   *string        `json:"acknowledged_by,omitempty"`
	AcknowledgedAt   *time.Time     `json:"acknowledged_at,omitempty"`
}

// List returns alerts for a tenant, newest first.
//
// Ordering is by severity then time rather than time alone: an on-call responder
// opening this page needs the worst thing first, not the most recent thing.
func (r *AlertRepo) List(ctx context.Context, tenantID string, onlyUnacknowledged bool, limit int) ([]AlertRow, error) {
	if limit <= 0 {
		limit = 100
	}
	query := `
		SELECT id, detection_id, detection_version, fired_at, severity, title,
		       evidence, linked_flow_ids, occurrence_count, delivery_state,
		       acknowledged_by, acknowledged_at
		FROM alert WHERE tenant_id = $1`
	if onlyUnacknowledged {
		query += ` AND acknowledged_at IS NULL`
	}
	query += `
		ORDER BY CASE severity
			WHEN 'critical' THEN 0 WHEN 'high' THEN 1
			WHEN 'medium' THEN 2 ELSE 3 END,
			fired_at DESC
		LIMIT $2`

	rows, err := r.pool.Query(ctx, query, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []AlertRow
	for rows.Next() {
		var a AlertRow
		var evidence []byte
		if err := rows.Scan(&a.AlertID, &a.DetectionID, &a.DetectionVersion, &a.FiredAt,
			&a.Severity, &a.Title, &evidence, &a.LinkedFlowIDs, &a.OccurrenceCount,
			&a.DeliveryState, &a.AcknowledgedBy, &a.AcknowledgedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(evidence, &a.Evidence)
		out = append(out, a)
	}
	return out, rows.Err()
}

// Acknowledge marks an alert as seen.
func (r *AlertRepo) Acknowledge(ctx context.Context, tenantID, alertID, principalID string) error {
	tag, err := r.pool.Exec(ctx, `
		UPDATE alert SET acknowledged_by = $3, acknowledged_at = now()
		WHERE tenant_id = $1 AND id = $2 AND acknowledged_at IS NULL`,
		tenantID, alertID, principalID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		// Either it does not exist, belongs to another tenant, or was already
		// acknowledged. The caller cannot distinguish these, which is deliberate.
		return fmt.Errorf("alert not available to acknowledge")
	}
	return nil
}
