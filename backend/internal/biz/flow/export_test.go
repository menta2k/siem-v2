package flow

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/menta2k/siem-v2/backend/internal/normalize/schema"
)

type fakeRaw struct {
	records []RawRecord
	err     error
}

func (f *fakeRaw) RawForFlow(context.Context, string, string) ([]RawRecord, error) {
	return f.records, f.err
}

func sampleFlow() *Flow {
	return &Flow{
		FlowID: "flow:ray:abc", Tenant: "acme",
		EffectiveOutcome: schema.ActionBlocked,
		Events: []schema.Event{{
			EventID: "cf-1", Provider: schema.ProviderCloudflare,
			MaskedFields: []string{"request.headers.authorization", "request.headers.cookie"},
		}},
	}
}

func exporter(raw *fakeRaw) *Exporter {
	return &Exporter{Raw: raw, Now: func() time.Time {
		return time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	}}
}

func TestExportCarriesRawRecordsAndProvenance(t *testing.T) {
	raw := &fakeRaw{records: []RawRecord{
		{RawID: "cf:1", Provider: schema.ProviderCloudflare, Payload: `{"RayID":"abc"}`},
		{RawID: "ngx:1", Provider: schema.ProviderNginx, Payload: `203.0.113.9 - ...`},
	}}
	pkg, err := exporter(raw).Export(context.Background(), sampleFlow(), ExportOptions{
		ExportedBy: "analyst@acme.example.com", TenantID: "acme", AuditRecordID: "audit-99",
	})
	if err != nil {
		t.Fatalf("export: %v", err)
	}

	if len(pkg.RawRecords) != 2 {
		t.Errorf("the originals must be included; a normalized flow alone is an interpretation")
	}
	if pkg.Provenance.ExportedBy == "" || pkg.Provenance.AuditRecordID != "audit-99" {
		t.Errorf("provenance incomplete: %+v", pkg.Provenance)
	}
	if pkg.Provenance.SchemaVersion == "" {
		t.Error("the schema version is needed to re-read the package years later")
	}
}

// TestUnattributedExportIsRefused: an export nobody is accountable for is not
// defensible, and producing one that looks complete would be worse than failing.
func TestUnattributedExportIsRefused(t *testing.T) {
	_, err := exporter(&fakeRaw{}).Export(context.Background(), sampleFlow(), ExportOptions{
		TenantID: "acme",
	})
	if err == nil {
		t.Fatal("an export with no attributed actor must be refused")
	}
}

// TestRedactionsAreNamedNotSilent: a package that silently omits fields looks
// complete and is not.
func TestRedactionsAreNamedNotSilent(t *testing.T) {
	pkg, err := exporter(&fakeRaw{}).Export(context.Background(), sampleFlow(), ExportOptions{
		ExportedBy: "analyst@acme.example.com", TenantID: "acme", IncludeSensitive: false,
	})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if len(pkg.Redactions) != 2 {
		t.Fatalf("withheld fields must be named, got %v", pkg.Redactions)
	}
	if pkg.Provenance.SensitiveIncluded {
		t.Error("the package must state that sensitive content was withheld")
	}

	full, err := exporter(&fakeRaw{}).Export(context.Background(), sampleFlow(), ExportOptions{
		ExportedBy: "admin@acme.example.com", TenantID: "acme", IncludeSensitive: true,
	})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if !full.Provenance.SensitiveIncluded {
		t.Error("an unmasked export must say so; the recipient needs to know which they hold")
	}
}

func TestExportFailsIfRawUnavailable(t *testing.T) {
	_, err := exporter(&fakeRaw{err: errors.New("storage down")}).Export(
		context.Background(), sampleFlow(), ExportOptions{
			ExportedBy: "a@example.com", TenantID: "acme",
		})
	if err == nil {
		t.Fatal("a package missing its raw records must fail rather than ship incomplete evidence")
	}
}

func TestMarshalRoundTrips(t *testing.T) {
	pkg, err := exporter(&fakeRaw{}).Export(context.Background(), sampleFlow(), ExportOptions{
		ExportedBy: "a@example.com", TenantID: "acme",
	})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	data, err := pkg.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back EvidencePackage
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("the package must be re-readable: %v", err)
	}
	if back.Flow.FlowID != pkg.Flow.FlowID {
		t.Error("flow identity lost in round trip")
	}
}

func TestNilFlowRefused(t *testing.T) {
	if _, err := exporter(&fakeRaw{}).Export(context.Background(), nil, ExportOptions{
		ExportedBy: "a@example.com",
	}); err == nil {
		t.Fatal("there is nothing to export")
	}
}

type stubLoader struct{ flow *Flow }

func (s *stubLoader) Get(context.Context, string, string) (*Flow, error) { return s.flow, nil }

func amenderFor(f *Flow, store Store) *Amender {
	return &Amender{
		Store: store, Loader: &stubLoader{flow: f},
		Now: func() time.Time { return time.Date(2026, 8, 19, 13, 0, 0, 0, time.UTC) },
	}
}

// TestLateRecordAmendsInPlace: two flows for one request is worse than one
// late-corrected flow (FR-018).
func TestLateRecordAmendsInPlace(t *testing.T) {
	closed := time.Date(2026, 8, 19, 12, 30, 0, 0, time.UTC)
	existing := &Flow{
		FlowID: "flow:ray:abc", Tenant: "acme", CorrelationKey: "ray:abc",
		ClosedAt: &closed,
		Events: []schema.Event{{
			EventID: "cf-1", Layer: schema.LayerEdge,
			EventTime: time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC),
			Verdict:   schema.Verdict{Action: schema.ActionAllowed, Mapped: true},
		}},
	}
	store := &captureStore{}
	late := schema.Event{
		EventID: "ngx-1", Layer: schema.LayerOrigin,
		EventTime: time.Date(2026, 8, 19, 12, 0, 1, 0, time.UTC),
		Verdict:   schema.Verdict{Action: schema.ActionAllowed, Mapped: true},
	}

	amended, err := amenderFor(existing, store).Amend(context.Background(), "acme", "ray:abc", late)
	if err != nil {
		t.Fatalf("amend: %v", err)
	}
	if len(amended.Events) != 2 {
		t.Fatalf("the late record must join the existing flow, got %d events", len(amended.Events))
	}
	if !amended.Amended {
		t.Error("the amendment must be visible; a flow that changed after someone read it matters")
	}
	if len(store.flows) != 1 {
		t.Fatalf("exactly one flow must be stored, not a second copy: got %d", len(store.flows))
	}
	if store.flows[0].FlowID != existing.FlowID {
		t.Error("the amended flow must keep its identity")
	}
}

func TestAmendIsIdempotent(t *testing.T) {
	existing := &Flow{
		FlowID: "flow:ray:abc", Tenant: "acme", CorrelationKey: "ray:abc",
		Events: []schema.Event{{EventID: "ngx-1", Layer: schema.LayerOrigin}},
	}
	store := &captureStore{}
	late := schema.Event{EventID: "ngx-1", Layer: schema.LayerOrigin}

	amended, err := amenderFor(existing, store).Amend(context.Background(), "acme", "ray:abc", late)
	if err != nil {
		t.Fatalf("amend: %v", err)
	}
	if len(amended.Events) != 1 {
		t.Fatalf("a redelivered late record must not duplicate a layer, got %d", len(amended.Events))
	}
}

func TestAmendReturnsNilForUnknownFlow(t *testing.T) {
	amended, err := amenderFor(nil, &captureStore{}).Amend(
		context.Background(), "acme", "ray:missing", schema.Event{EventID: "x"})
	if err != nil {
		t.Fatalf("a missing flow is not an error: %v", err)
	}
	if amended != nil {
		t.Error("with no flow to amend, the caller should open a new one rather than be handed a fake")
	}
}
