package datadome

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/menta2k/siem-v2/backend/internal/normalize/schema"
)

var receivedAt = time.Date(2026, 8, 19, 12, 0, 5, 0, time.UTC)

func loadExport(t *testing.T) [][]byte {
	t.Helper()
	data, err := os.ReadFile("../../../test/fixtures/datadome/logs_export.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var records []json.RawMessage
	if err := json.Unmarshal(data, &records); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	out := make([][]byte, len(records))
	for i, r := range records {
		out[i] = r
	}
	return out
}

func TestParsePullExportShape(t *testing.T) {
	records := loadExport(t)
	if len(records) != 3 {
		t.Fatalf("expected 3 fixture records, got %d", len(records))
	}
	p := New()

	blocked, err := p.Parse(records[0], receivedAt)
	if err != nil {
		t.Fatalf("parse blocked: %v", err)
	}
	if blocked.Verdict.Action != schema.ActionBlocked {
		t.Errorf("action: want blocked, got %q", blocked.Verdict.Action)
	}
	if blocked.Layer != schema.LayerBotManagement {
		t.Errorf("layer: want bot_management, got %q", blocked.Layer)
	}
	if blocked.VendorRequestID != "dd-req-99" {
		t.Errorf("vendor request id: got %q", blocked.VendorRequestID)
	}
	if blocked.Verdict.Score == nil || *blocked.Verdict.Score != 12 {
		t.Errorf("bot score should be carried: %v", blocked.Verdict.Score)
	}

	allowed, err := p.Parse(records[1], receivedAt)
	if err != nil {
		t.Fatalf("parse allowed: %v", err)
	}
	if allowed.Verdict.Action != schema.ActionAllowed {
		t.Errorf("want allowed, got %q", allowed.Verdict.Action)
	}

	captcha, err := p.Parse(records[2], receivedAt)
	if err != nil {
		t.Fatalf("parse captcha: %v", err)
	}
	if captcha.Verdict.Action != schema.ActionChallenged {
		t.Errorf("captcha maps to challenged, got %q", captcha.Verdict.Action)
	}
}

// TestParseHeaderShapeEquivalence is the reason both shapes share one parser:
// the same decision delivered either way must normalize identically, or the two
// paths will drift and the same request will read differently depending on how
// it was collected.
func TestParseHeaderShapeEquivalence(t *testing.T) {
	pull := []byte(`{"requestid":"dd-req-99","timestamp":"2026-08-19T12:00:00.150Z","action":"block","botscore":12,"botname":"scrapy","ruletype":"AI Threats"}`)
	header := []byte(`{"x-datadome-requestid":"dd-req-99","timestamp":"2026-08-19T12:00:00.150Z","x-datadome-action":"block","x-datadome-botscore":"12","x-datadome-botname":"scrapy","x-datadome-ruletype":"AI Threats"}`)

	p := New()
	a, err := p.Parse(pull, receivedAt)
	if err != nil {
		t.Fatalf("parse pull shape: %v", err)
	}
	b, err := p.Parse(header, receivedAt)
	if err != nil {
		t.Fatalf("parse header shape: %v", err)
	}

	if a.Verdict.Action != b.Verdict.Action {
		t.Errorf("action differs between shapes: %q vs %q", a.Verdict.Action, b.Verdict.Action)
	}
	if a.VendorRequestID != b.VendorRequestID {
		t.Errorf("request id differs: %q vs %q", a.VendorRequestID, b.VendorRequestID)
	}
	if a.Verdict.Score == nil || b.Verdict.Score == nil || *a.Verdict.Score != *b.Verdict.Score {
		t.Errorf("score differs: %v vs %v", a.Verdict.Score, b.Verdict.Score)
	}
	if a.Verdict.RuleName != b.Verdict.RuleName {
		t.Errorf("bot name differs: %q vs %q", a.Verdict.RuleName, b.Verdict.RuleName)
	}
}

func TestDataDomeIdentifierIsNamespaced(t *testing.T) {
	e, err := New().Parse(loadExport(t)[0], receivedAt)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(e.Identifiers) != 1 || e.Identifiers[0] != "dd:dd-req-99" {
		t.Fatalf("expected one dd-namespaced identifier, got %v", e.Identifiers)
	}
}

func TestUnknownActionSurfaced(t *testing.T) {
	e, err := New().Parse([]byte(`{"requestid":"x1","timestamp":"2026-08-19T12:00:00Z","action":"quarantine"}`), receivedAt)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.Verdict.Mapped || e.Verdict.Action != schema.ActionUnknown {
		t.Errorf("unfamiliar action must be unmapped/unknown, got %q mapped=%v", e.Verdict.Action, e.Verdict.Mapped)
	}
	if e.Verdict.ReasonRaw["action"] != "quarantine" {
		t.Error("original action value must survive verbatim")
	}
}

func TestRecordWithoutRequestIDRejected(t *testing.T) {
	if _, err := New().Parse([]byte(`{"ip":"203.0.113.1","action":"allow"}`), receivedAt); err == nil {
		t.Fatal("without a requestid the record cannot be correlated and must be dead-lettered")
	}
}

func TestNumericAndStringScoresBothParse(t *testing.T) {
	// The pull export sends botscore as a number; the header shape sends it as a
	// string. Both must land in the same typed field.
	p := New()
	num, err := p.Parse([]byte(`{"requestid":"a","timestamp":"2026-08-19T12:00:00Z","action":"allow","botscore":42}`), receivedAt)
	if err != nil {
		t.Fatalf("numeric score: %v", err)
	}
	str, err := p.Parse([]byte(`{"requestid":"b","timestamp":"2026-08-19T12:00:00Z","action":"allow","botscore":"42"}`), receivedAt)
	if err != nil {
		t.Fatalf("string score: %v", err)
	}
	if num.Verdict.Score == nil || str.Verdict.Score == nil || *num.Verdict.Score != *str.Verdict.Score {
		t.Fatalf("score should parse identically from both encodings: %v vs %v", num.Verdict.Score, str.Verdict.Score)
	}
}

func TestTimestampLayouts(t *testing.T) {
	p := New()
	for _, ts := range []string{
		`"2026-08-19T12:00:00.150Z"`,
		`"2026-08-19 12:00:00"`,
		`1787054400150`,
	} {
		raw := []byte(`{"requestid":"x","action":"allow","timestamp":` + ts + `}`)
		e, err := p.Parse(raw, receivedAt)
		if err != nil {
			t.Errorf("timestamp %s should parse: %v", ts, err)
			continue
		}
		if e.EventTime.IsZero() {
			t.Errorf("timestamp %s produced a zero time", ts)
		}
	}
	if _, err := p.Parse([]byte(`{"requestid":"x","action":"allow","timestamp":"last tuesday"}`), receivedAt); err == nil {
		t.Error("an unparseable timestamp must dead-letter rather than default to zero")
	}
}

func TestMissingActionIsUnmapped(t *testing.T) {
	e, err := New().Parse([]byte(`{"requestid":"x","timestamp":"2026-08-19T12:00:00Z"}`), receivedAt)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.Verdict.Mapped {
		t.Error("no action reported means we do not know the decision, not that it was allowed")
	}
}

func TestHostAndMethodExtracted(t *testing.T) {
	e, err := New().Parse(loadExport(t)[1], receivedAt)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.Request.Host != "shop.example.com" || e.Request.Method != "POST" || e.Request.Path != "/cart" {
		t.Errorf("request attributes: host=%q method=%q path=%q", e.Request.Host, e.Request.Method, e.Request.Path)
	}
	if e.Client.Country != "US" {
		t.Errorf("country should be upper-cased: %q", e.Client.Country)
	}
}

func TestMalformedJSONRejected(t *testing.T) {
	if _, err := New().Parse([]byte(`{"requestid":`), receivedAt); err == nil {
		t.Fatal("malformed JSON must produce a parse error")
	}
}
