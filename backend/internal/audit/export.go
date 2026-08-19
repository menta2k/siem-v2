// Package audit exports the trail to immutable storage.
package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// Entry is one exported audit record.
type Entry struct {
	TenantID    string         `json:"tenant_id"`
	PrincipalID string         `json:"principal_id"`
	Action      string         `json:"action"`
	Scope       string         `json:"scope"`
	TargetRef   string         `json:"target_ref,omitempty"`
	OccurredAt  time.Time      `json:"occurred_at"`
	Outcome     string         `json:"outcome"`
	Detail      map[string]any `json:"detail,omitempty"`
}

// Reader supplies entries for export.
type Reader interface {
	Since(ctx context.Context, tenantID string, from, to time.Time) ([]Entry, error)
}

// ImmutableWriter stores an export where it cannot be altered.
type ImmutableWriter interface {
	// PutLocked writes the object and applies retention. The retention is what
	// makes the export evidence rather than a copy.
	PutLocked(ctx context.Context, key string, body []byte, retainUntil time.Time) error
}

// Exporter writes periodic immutable snapshots of the audit trail.
//
// PostgreSQL grants and the append-only trigger prevent modification in place;
// this export is what makes the trail survive the database itself. The two
// together are the FR-055 guarantee: one stops an operator editing history, the
// other stops them destroying it.
type Exporter struct {
	Reader    Reader
	Writer    ImmutableWriter
	Retention time.Duration
	Now       func() time.Time
}

// Manifest describes an export, including a digest of its contents.
//
// The digest is the point: an export whose integrity cannot be demonstrated is
// a copy, not evidence. It lets a later reader prove the file is the one that
// was written without trusting the storage layer.
type Manifest struct {
	TenantID    string    `json:"tenant_id"`
	From        time.Time `json:"from"`
	To          time.Time `json:"to"`
	EntryCount  int       `json:"entry_count"`
	SHA256      string    `json:"sha256"`
	ExportedAt  time.Time `json:"exported_at"`
	RetainUntil time.Time `json:"retain_until"`
}

// Export writes one window of the audit trail to immutable storage.
func (e *Exporter) Export(ctx context.Context, tenantID string, from, to time.Time) (*Manifest, error) {
	if !to.After(from) {
		return nil, fmt.Errorf("export window must end after it starts")
	}

	entries, err := e.Reader.Since(ctx, tenantID, from, to)
	if err != nil {
		return nil, fmt.Errorf("read audit entries: %w", err)
	}
	if len(entries) == 0 {
		// An empty window is not an error, and writing an empty object would
		// create a gap that looks identical to a missing export.
		return nil, nil
	}

	body, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode audit export: %w", err)
	}

	sum := sha256.Sum256(body)
	now := e.now()
	retainUntil := now.Add(e.retention())

	key := fmt.Sprintf("audit/%s/%s.json", tenantID, from.UTC().Format("2006-01-02T15-04-05"))
	if err := e.Writer.PutLocked(ctx, key, body, retainUntil); err != nil {
		return nil, fmt.Errorf("write immutable audit export: %w", err)
	}

	return &Manifest{
		TenantID: tenantID, From: from, To: to,
		EntryCount: len(entries), SHA256: hex.EncodeToString(sum[:]),
		ExportedAt: now, RetainUntil: retainUntil,
	}, nil
}

func (e *Exporter) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now().UTC()
}

func (e *Exporter) retention() time.Duration {
	if e.Retention > 0 {
		return e.Retention
	}
	// Seven years by default: long enough for the regulatory regimes an audit
	// trail is usually kept for, and a deliberate over-estimate because
	// shortening a retention later is easy and lengthening it retroactively is
	// impossible.
	return 7 * 365 * 24 * time.Hour
}
