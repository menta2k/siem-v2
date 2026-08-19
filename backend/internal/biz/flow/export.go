package flow

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/menta2k/siem-v2/backend/internal/normalize/schema"
)

// EvidencePackage is a defensible export of one request flow.
//
// It carries its own provenance because an export that cannot say who produced
// it, when, and from what is not evidence — it is just a file (FR-041, FR-042).
type EvidencePackage struct {
	Flow       *Flow       `json:"flow"`
	RawRecords []RawRecord `json:"raw_records"`
	Provenance Provenance  `json:"provenance"`
	Redactions []string    `json:"redactions,omitempty"`
}

// RawRecord is one contributing provider record in its original form.
type RawRecord struct {
	RawID      string          `json:"raw_id"`
	Provider   schema.Provider `json:"provider"`
	ReceivedAt time.Time       `json:"received_at"`
	Payload    string          `json:"payload"`
	// Fields masked before storage. Named rather than silently absent, so a
	// recipient can tell the difference between "not present" and "withheld".
	MaskedFields []string `json:"masked_fields,omitempty"`
}

// Provenance records how the package came to exist.
type Provenance struct {
	ExportedBy    string    `json:"exported_by"`
	ExportedAt    time.Time `json:"exported_at"`
	AuditRecordID string    `json:"audit_record_id"`
	TenantID      string    `json:"tenant_id"`
	SchemaVersion string    `json:"schema_version"`
	// SensitiveIncluded states plainly whether classified fields were unmasked
	// for this export. An investigator receiving the package must know which of
	// the two things they are holding.
	SensitiveIncluded bool `json:"sensitive_included"`
}

// RawFetcher retrieves the original records contributing to a flow.
type RawFetcher interface {
	RawForFlow(ctx context.Context, tenantID, flowID string) ([]RawRecord, error)
}

// Exporter builds evidence packages.
type Exporter struct {
	Raw RawFetcher
	Now func() time.Time
}

// ExportOptions controls what the package contains.
type ExportOptions struct {
	ExportedBy       string
	TenantID         string
	AuditRecordID    string
	IncludeSensitive bool
}

// Export assembles the package.
//
// Raw records are included because a normalized flow alone is an interpretation:
// re-deriving it, or challenging it, requires what the providers actually sent
// (Constitution Principle II).
func (e *Exporter) Export(ctx context.Context, f *Flow, opts ExportOptions) (*EvidencePackage, error) {
	if f == nil {
		return nil, fmt.Errorf("no flow to export")
	}
	if opts.ExportedBy == "" {
		// An export with no attributed actor is not defensible, so refuse rather
		// than produce one that looks complete.
		return nil, fmt.Errorf("an evidence export must record who produced it")
	}

	raw, err := e.Raw.RawForFlow(ctx, opts.TenantID, f.FlowID)
	if err != nil {
		return nil, fmt.Errorf("fetch contributing records: %w", err)
	}

	pkg := &EvidencePackage{
		Flow:       f,
		RawRecords: raw,
		Provenance: Provenance{
			ExportedBy:        opts.ExportedBy,
			ExportedAt:        e.now(),
			AuditRecordID:     opts.AuditRecordID,
			TenantID:          opts.TenantID,
			SchemaVersion:     schema.Version,
			SensitiveIncluded: opts.IncludeSensitive,
		},
	}

	if !opts.IncludeSensitive {
		pkg.Redactions = collectRedactions(f)
	}
	return pkg, nil
}

// collectRedactions lists what was withheld.
//
// Naming the redactions matters: a package that silently omits fields looks
// complete and is not, which is exactly the confusion an evidence package must
// not create.
func collectRedactions(f *Flow) []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range f.Events {
		for _, field := range e.MaskedFields {
			if !seen[field] {
				seen[field] = true
				out = append(out, field)
			}
		}
	}
	return out
}

// Marshal renders the package for download.
func (p *EvidencePackage) Marshal() ([]byte, error) {
	return json.MarshalIndent(p, "", "  ")
}

func (e *Exporter) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now().UTC()
}
