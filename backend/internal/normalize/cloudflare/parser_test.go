package cloudflare

import (
	"bufio"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/menta2k/siem-v2/backend/internal/normalize/schema"
)

func loadLines(t *testing.T, path string) [][]byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer f.Close()
	var out [][]byte
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" {
			out = append(out, []byte(line))
		}
	}
	return out
}

var receivedAt = time.Date(2026, 8, 19, 12, 0, 5, 0, time.UTC)

func TestParseModernSecurityFields(t *testing.T) {
	lines := loadLines(t, "../../../test/fixtures/cloudflare/http_requests_modern.ndjson")
	if len(lines) != 3 {
		t.Fatalf("expected 3 fixture records, got %d", len(lines))
	}
	p := New()

	blocked, err := p.Parse(lines[0], receivedAt)
	if err != nil {
		t.Fatalf("parse blocked record: %v", err)
	}
	if blocked.Verdict.Action != schema.ActionBlocked {
		t.Errorf("action: want blocked, got %q", blocked.Verdict.Action)
	}
	if !blocked.Verdict.Terminating {
		t.Error("a block terminates the request")
	}
	if blocked.Verdict.RuleID != "100015" {
		t.Errorf("rule id: want 100015, got %q", blocked.Verdict.RuleID)
	}
	if blocked.Request.Path != "/search" || blocked.Request.Query == "" {
		t.Errorf("URI split: path=%q query=%q", blocked.Request.Path, blocked.Request.Query)
	}
	if blocked.Layer != schema.LayerEdge {
		t.Errorf("layer: want edge, got %q", blocked.Layer)
	}
	if blocked.Response.DurationMS < 300 || blocked.Response.DurationMS > 320 {
		t.Errorf("duration from edge start/end: got %v ms, want ~312", blocked.Response.DurationMS)
	}

	allowed, err := p.Parse(lines[1], receivedAt)
	if err != nil {
		t.Fatalf("parse allowed record: %v", err)
	}
	if allowed.Verdict.Action != schema.ActionAllowed {
		t.Errorf("empty SecurityAction means the edge took no security action: got %q", allowed.Verdict.Action)
	}
	if !allowed.Verdict.Mapped {
		t.Error("an absent security decision is a known state, not an unmapped one")
	}

	challenged, err := p.Parse(lines[2], receivedAt)
	if err != nil {
		t.Fatalf("parse challenged record: %v", err)
	}
	if challenged.Verdict.Action != schema.ActionChallenged {
		t.Errorf("managed_challenge should map to challenged, got %q", challenged.Verdict.Action)
	}
}

// TestParseCarriesBothIdentifiers is the case the whole correlation design rests
// on: the Cloudflare record must expose the Ray ID AND the DataDome request id,
// because it is the only record that knows both (research.md R11a).
func TestParseCarriesBothIdentifiers(t *testing.T) {
	lines := loadLines(t, "../../../test/fixtures/cloudflare/http_requests_modern.ndjson")
	e, err := New().Parse(lines[0], receivedAt)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(e.Identifiers) != 2 {
		t.Fatalf("expected the ray id AND the datadome request id, got %v", e.Identifiers)
	}
	var hasRay, hasDD bool
	for _, id := range e.Identifiers {
		switch {
		case strings.HasPrefix(id, "ray:"):
			hasRay = true
		case strings.HasPrefix(id, "dd:"):
			hasDD = true
		}
	}
	if !hasRay || !hasDD {
		t.Fatalf("bridge requires both identifier spaces, got %v", e.Identifiers)
	}
	if e.Bot == nil || !e.Bot.DataDomePresent {
		t.Error("DataDome enrichment should be detected as present")
	}
}

// TestMissingDataDomeFieldsAreFlagged: absent custom fields are a configuration
// fault, not evidence that no bot decision was made.
func TestMissingDataDomeFieldsAreFlagged(t *testing.T) {
	lines := loadLines(t, "../../../test/fixtures/cloudflare/http_requests_modern.ndjson")
	e, err := New().Parse(lines[2], receivedAt) // third record has no RequestHeaders
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !e.HasFlag(schema.FlagDataDomeFieldsAbsent) {
		t.Error("missing x-datadome-requestid must raise datadome_fields_absent; " +
			"silently producing a flow without the bot layer hides a misconfigured Logpush job")
	}
	if len(e.Identifiers) != 1 {
		t.Errorf("without the DataDome header there is no bridge, only the ray id: got %v", e.Identifiers)
	}
}

// TestParseLegacyFieldFamily covers V5: which family a zone populates is
// unverified, so both must work.
func TestParseLegacyFieldFamily(t *testing.T) {
	lines := loadLines(t, "../../../test/fixtures/cloudflare/http_requests_legacy.ndjson")
	p := New()

	blocked, err := p.Parse(lines[0], receivedAt)
	if err != nil {
		t.Fatalf("parse legacy blocked: %v", err)
	}
	if blocked.Verdict.Action != schema.ActionBlocked {
		t.Errorf("legacy drop should map to blocked, got %q", blocked.Verdict.Action)
	}
	if blocked.Verdict.RuleID != "981176" {
		t.Errorf("legacy rule id: got %q", blocked.Verdict.RuleID)
	}
	if fam := blocked.Verdict.ReasonRaw["field_family"]; fam != "legacy" {
		t.Errorf("the field family actually used must be recorded, got %v", fam)
	}
	// Epoch-nanosecond timestamps are the API default format.
	if blocked.EventTime.IsZero() {
		t.Error("epoch-nanosecond EdgeStartTimestamp must parse")
	}

	allowed, err := p.Parse(lines[1], receivedAt)
	if err != nil {
		t.Fatalf("parse legacy allowed: %v", err)
	}
	if allowed.Verdict.Action != schema.ActionAllowed {
		t.Errorf("WAFAction=1 is allow, got %q", allowed.Verdict.Action)
	}
}

// TestUnknownActionIsSurfacedNotCoerced is FR-014: a security tool must not round
// an unfamiliar decision to the nearest known one.
func TestUnknownActionIsSurfacedNotCoerced(t *testing.T) {
	lines := loadLines(t, "../../../test/fixtures/cloudflare/http_requests_unmapped.ndjson")
	e, err := New().Parse(lines[0], receivedAt)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.Verdict.Mapped {
		t.Error("an unrecognized action must be marked unmapped")
	}
	if e.Verdict.Action != schema.ActionUnknown {
		t.Errorf("want unknown, got %q — never guess at an unfamiliar verdict", e.Verdict.Action)
	}
	if !e.HasFlag(schema.FlagUnmappedValues) {
		t.Error("unmapped values must raise a data-quality flag")
	}
	if got := e.Verdict.ReasonRaw["SecurityAction"]; got != "quantum_shield_v3" {
		t.Errorf("the original value must survive verbatim, got %v", got)
	}
}

func TestRecordWithoutRayIDIsRejected(t *testing.T) {
	_, err := New().Parse([]byte(`{"ClientIP":"203.0.113.1","EdgeResponseStatus":200}`), receivedAt)
	if err == nil {
		t.Fatal("a record with no RayID cannot be correlated or deduplicated and must be dead-lettered")
	}
}

func TestMalformedJSONIsRejected(t *testing.T) {
	if _, err := New().Parse([]byte(`{"RayID":`), receivedAt); err == nil {
		t.Fatal("malformed JSON must produce a parse error, not a partial event")
	}
}

// TestCamelCaseSecurityActionsMap covers the form Cloudflare's current ruleset
// actually emits (managedChallenge, connectionClose), which lowercases to a
// concatenated token the snake_case-only table used to miss — sending the single
// most common security action, a managed challenge, to "unknown".
func TestCamelCaseSecurityActionsMap(t *testing.T) {
	cases := []struct {
		action string
		want   schema.Action
	}{
		{"managedChallenge", schema.ActionChallenged},
		{"jsChallenge", schema.ActionChallenged},
		{"connectionClose", schema.ActionBlocked},
		{"forceConnectionClose", schema.ActionBlocked},
		{"managedChallengeNonInteractiveSolved", schema.ActionChallengePassed},
		{"managedChallengeInteractiveSolved", schema.ActionChallengePassed},
		{"managedChallengeBypassed", schema.ActionAllowed},
	}
	for _, c := range cases {
		line := []byte(`{"RayID":"a2e1279f0d9a52f4","ParentRayID":"00",` +
			`"EdgeStartTimestamp":"2026-08-20T11:45:57Z","ClientIP":"1.2.3.4",` +
			`"ClientRequestHost":"www.jobs.bg","ClientRequestURI":"/.env",` +
			`"ClientRequestMethod":"GET","EdgeResponseStatus":403,` +
			`"SecurityAction":"` + c.action + `"}`)
		e, err := New().Parse(line, receivedAt)
		if err != nil {
			t.Fatalf("parse %s: %v", c.action, err)
		}
		if e.Verdict.Action != c.want {
			t.Errorf("%s: want %q, got %q", c.action, c.want, e.Verdict.Action)
		}
		if !e.Verdict.Mapped {
			t.Errorf("%s: should be mapped, not surfaced as unknown", c.action)
		}
	}
}
