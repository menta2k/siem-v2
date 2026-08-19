package f5asm

import (
	"bufio"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/menta2k/siem-v2/backend/internal/normalize/schema"
)

var receivedAt = time.Date(2026, 8, 19, 12, 0, 5, 0, time.UTC)

func lines(t *testing.T) []string {
	t.Helper()
	f, err := os.Open("../../../test/fixtures/f5asm/asm_kv.log")
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" {
			out = append(out, l)
		}
	}
	return out
}

func TestParseBlockedViolation(t *testing.T) {
	e, err := New().Parse([]byte(lines(t)[0]), receivedAt)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.Verdict.Action != schema.ActionBlocked || !e.Verdict.Terminating {
		t.Errorf("blocked request: action=%q terminating=%v", e.Verdict.Action, e.Verdict.Terminating)
	}
	if e.Verdict.RuleID != "200001834" {
		t.Errorf("signature id: got %q", e.Verdict.RuleID)
	}
	if e.Verdict.Category != "SQL-Injection" {
		t.Errorf("attack type: got %q", e.Verdict.Category)
	}
	if e.Layer != schema.LayerAppFirewall {
		t.Errorf("layer: got %q", e.Layer)
	}
	if e.Client.IP != "203.0.113.9" {
		t.Errorf("client ip: got %q", e.Client.IP)
	}
}

// TestCFRayRecoveredFromRawRequest covers the V2 fallback: if the logging profile
// cannot emit an arbitrary header field, an iRule can still put CF-Ray into the
// captured request text, and that must be enough for an exact join.
func TestCFRayRecoveredFromRawRequest(t *testing.T) {
	e, err := New().Parse([]byte(lines(t)[0]), receivedAt)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.RayID != "8f2a3b4c5d6e7f01" {
		t.Fatalf("CF-Ray must be recovered from the captured request, got %q", e.RayID)
	}
	if len(e.Identifiers) != 1 || e.Identifiers[0] != "ray:8f2a3b4c5d6e7f01" {
		t.Fatalf("expected a ray identifier, got %v", e.Identifiers)
	}
	// The datacentre suffix on the wire ("-FRA") is not part of the id Cloudflare
	// logs; including it would make every F5 join miss.
	if strings.Contains(e.RayID, "-") {
		t.Errorf("ray id must exclude the datacentre suffix, got %q", e.RayID)
	}
}

func TestPreferDedicatedCFRayFieldOverRawRequest(t *testing.T) {
	rec := `support_id="1",date_time="2026-08-19 12:00:00",request_status="passed",cf_ray="aaaa1111bbbb2222",request="GET / HTTP/1.1\r\nCF-Ray: ffff9999eeee8888-LHR\r\n\r\n"`
	e, err := New().Parse([]byte(rec), receivedAt)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.RayID != "aaaa1111bbbb2222" {
		t.Errorf("a dedicated field is more reliable than scraping raw text; got %q", e.RayID)
	}
}

// TestMissingCFRayFlagged makes the V2 failure mode visible instead of silent.
func TestMissingCFRayFlagged(t *testing.T) {
	rec := `support_id="2",date_time="2026-08-19 12:00:00",request_status="blocked",violations="Attack signature detected",request="GET / HTTP/1.1\r\nHost: x.example.com\r\n\r\n"`
	e, err := New().Parse([]byte(rec), receivedAt)
	if err != nil {
		t.Fatalf("a record without CF-Ray still carries the WAF verdict and must parse: %v", err)
	}
	if !e.HasFlag(schema.FlagNoCorrelationKey) {
		t.Error("no ray id means heuristic-only joining; that degradation must be flagged")
	}
}

func TestAlertedIsLoggedNotBlocked(t *testing.T) {
	rec := `support_id="3",date_time="2026-08-19 12:00:00",request_status="alerted",violations="Illegal parameter",sig_ids="200001",attack_type="Parameter Tampering"`
	e, err := New().Parse([]byte(rec), receivedAt)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.Verdict.Action != schema.ActionLogged {
		t.Errorf("alerted means detected-not-blocked; got %q — conflating it with a block "+
			"overstates what the WAF did", e.Verdict.Action)
	}
	if e.Verdict.Terminating {
		t.Error("an alert does not terminate the request")
	}
}

func TestNAPlaceholdersAreNormalized(t *testing.T) {
	e, err := New().Parse([]byte(lines(t)[1]), receivedAt) // passed record with attack_type="N/A"
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.Verdict.Category == "N/A" {
		t.Error(`ASM's "N/A" placeholder must not surface as a real attack type`)
	}
}

func TestUnparseableRecordRejected(t *testing.T) {
	if _, err := New().Parse([]byte("this is not key-value ASM output"), receivedAt); err == nil {
		t.Fatal("a record with no kv pairs must be dead-lettered")
	}
}

// TestSupportIDIsSurfacedAsTheVendorReference.
//
// The support_id is what an operator reads off the ASM console and quotes to F5
// support. It is not a correlation key — it means nothing to Cloudflare or nginx
// — but without it an investigation that begins in ASM has no way into this
// system.
func TestSupportIDIsSurfacedAsTheVendorReference(t *testing.T) {
	e, err := New().Parse([]byte(lines(t)[0]), receivedAt)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.VendorRequestID != "4823905718293847" {
		t.Errorf("support_id should be the vendor reference, got %q", e.VendorRequestID)
	}
	// It must NOT be mistaken for a correlation identifier.
	for _, id := range e.Identifiers {
		if strings.Contains(id, e.VendorRequestID) {
			t.Error("support_id must not be used as a join key; no other provider knows it")
		}
	}
}
