package nginx

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
	f, err := os.Open("../../../test/fixtures/nginx/access.ndjson")
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" {
			out = append(out, l)
		}
	}
	return out
}

func TestParseAccessLine(t *testing.T) {
	ls := lines(t)
	e, err := New().Parse([]byte(ls[0]), receivedAt)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.Client.IP != "203.0.113.9" {
		t.Errorf("client ip: got %q", e.Client.IP)
	}
	if e.Request.Method != "GET" || e.Request.Path != "/search" {
		t.Errorf("request line: method=%q path=%q", e.Request.Method, e.Request.Path)
	}
	if e.Request.Query == "" {
		t.Error("query string should be separated from the path")
	}
	if e.Response.Status != 403 || e.Response.Bytes != 153 {
		t.Errorf("response: status=%d bytes=%d", e.Response.Status, e.Response.Bytes)
	}
	if e.Layer != schema.LayerOrigin {
		t.Errorf("nginx is the origin layer, got %q", e.Layer)
	}
	if e.Response.DurationMS < 311 || e.Response.DurationMS > 313 {
		t.Errorf("request_time should convert to ms: got %v", e.Response.DurationMS)
	}
}

// TestCFRayEnablesExactJoin is why the log_format matters.
func TestCFRayEnablesExactJoin(t *testing.T) {
	e, err := New().Parse([]byte(lines(t)[0]), receivedAt)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.RayID != "8f2a3b4c5d6e7f01" {
		t.Errorf("ray id must be extracted from $http_cf_ray, got %q", e.RayID)
	}
	if len(e.Identifiers) != 1 || e.Identifiers[0] != "ray:8f2a3b4c5d6e7f01" {
		t.Fatalf("expected a ray-namespaced identifier, got %v", e.Identifiers)
	}
	if e.CorrelationKeySource != schema.KeySourceRayID {
		t.Errorf("key source: got %q", e.CorrelationKeySource)
	}
}

// TestMissingCFRayIsFlaggedNotFatal: a line without the header is still useful
// data. Dropping it would lose origin visibility; silently accepting it would
// hide that correlation quality has degraded.
func TestMissingCFRayIsFlaggedNotFatal(t *testing.T) {
	ls := lines(t)
	e, err := New().Parse([]byte(ls[2]), receivedAt) // third line logs "-"
	if err != nil {
		t.Fatalf("a missing cf_ray must not fail the parse: %v", err)
	}
	if len(e.Identifiers) != 0 {
		t.Errorf("a dash is not an identifier, got %v", e.Identifiers)
	}
	if !e.HasFlag(schema.FlagNoCorrelationKey) {
		t.Error("missing correlation key must be flagged so the exact-join ratio stays meaningful")
	}
}

func TestOriginStatusIsNotATerminatingSecurityVerdict(t *testing.T) {
	e, err := New().Parse([]byte(lines(t)[0]), receivedAt) // 403
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.Verdict.Terminating {
		t.Error("nginx reports an outcome, not a security decision; " +
			"marking it terminating would attribute an upstream WAF block to the origin")
	}
}

func TestMalformedLineRejected(t *testing.T) {
	if _, err := New().Parse([]byte("not an access log line"), receivedAt); err == nil {
		t.Fatal("a line that does not match log_format must be dead-lettered, not half-parsed")
	}
}

// TestEventIDIsDeterministicAndUnique guards two properties at once: redelivery
// must not create a second event (FR-007), and two different lines must not
// collide into one (which would silently drop origin records from flows).
func TestEventIDIsDeterministicAndUnique(t *testing.T) {
	ls := lines(t)
	p := New()

	first, err := p.Parse([]byte(ls[0]), receivedAt)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	again, err := p.Parse([]byte(ls[0]), receivedAt.Add(time.Hour))
	if err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	if first.EventID == "" {
		t.Fatal("every event needs an id, or it cannot be deduplicated or referenced")
	}
	if first.EventID != again.EventID {
		t.Errorf("redelivery must yield the same id: %q vs %q", first.EventID, again.EventID)
	}

	other, err := p.Parse([]byte(ls[1]), receivedAt)
	if err != nil {
		t.Fatalf("parse second line: %v", err)
	}
	if other.EventID == first.EventID {
		t.Error("different lines must not share an id")
	}
}

// TestRayIDStripsDatacentreSuffix is a correlation-breaking bug found against
// real data: nginx receives CF-Ray as "<id>-<COLO>" on the wire, but Cloudflare
// logs only the bare id. Keeping the suffix meant every origin record failed to
// join its Cloudflare record — correlation still "worked", just far worse, with
// nothing to indicate why.
func TestRayIDStripsDatacentreSuffix(t *testing.T) {
	cases := map[string]string{
		"a2d6ea0f6813ccd4-DXB": "a2d6ea0f6813ccd4",
		"8f2a3b4c5d6e7f01-FRA": "8f2a3b4c5d6e7f01",
		"8f2a3b4c5d6e7f01":     "8f2a3b4c5d6e7f01",
		"-":                    "",
		"":                     "",
	}
	for in, want := range cases {
		if got := NormalizeRayID(in); got != want {
			t.Errorf("NormalizeRayID(%q) = %q, want %q", in, got, want)
		}
	}

	e, err := New().Parse([]byte(lines(t)[0]), receivedAt)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(e.RayID) != 16 {
		t.Errorf("ray id %q must be the 16-char form Cloudflare logs, or the join misses", e.RayID)
	}
}

// TestClientIPPrefersCFConnectingIP: behind Cloudflare, remote_addr is an edge
// address. Reporting it as the client would attribute every request to the CDN.
func TestClientIPPrefersCFConnectingIP(t *testing.T) {
	e, err := New().Parse([]byte(lines(t)[0]), receivedAt)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.Client.IP != "203.0.113.9" {
		t.Errorf("expected the true client from cf_connecting_ip, got %q", e.Client.IP)
	}

	// Falls back to the left-most X-Forwarded-For entry, which is the original client.
	second, err := New().Parse([]byte(lines(t)[1]), receivedAt)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if second.Client.IP != "198.51.100.42" {
		t.Errorf("expected the left-most XFF entry, got %q", second.Client.IP)
	}
}

func TestNumericFieldsAcceptBothEncodings(t *testing.T) {
	// A JSON log_format writes numbers unquoted, but some builds and some fields
	// quote them. A parser handling only one would silently read zero.
	quoted := `{"time_iso8601":"2026-08-19T12:00:00+00:00","cf_ray":"abc123-FRA","request_uri":"/x","status":"404","body_bytes_sent":"512","request_time":"1.5"}`
	e, err := New().Parse([]byte(quoted), receivedAt)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.Response.Status != 404 {
		t.Errorf("quoted status should parse, got %d", e.Response.Status)
	}
	if e.Response.Bytes != 512 {
		t.Errorf("quoted bytes should parse, got %d", e.Response.Bytes)
	}
	if e.Response.DurationMS != 1500 {
		t.Errorf("quoted request_time should convert to ms, got %v", e.Response.DurationMS)
	}
}

func TestStatusMapping(t *testing.T) {
	cases := map[int]schema.Action{
		200: schema.ActionAllowed,
		301: schema.ActionAllowed,
		401: schema.ActionBlocked,
		403: schema.ActionBlocked,
		429: schema.ActionRateLimited,
		500: schema.ActionAllowed, // an origin error is not a security decision
	}
	for status, want := range cases {
		if got := statusToAction(status); got != want {
			t.Errorf("status %d: want %q, got %q", status, want, got)
		}
	}
}

func TestMalformedRecordsRejected(t *testing.T) {
	for name, body := range map[string]string{
		"not json":      `203.0.113.9 - - [19/Aug/2026] "GET / HTTP/1.1" 200`,
		"empty object":  `{}`,
		"bad timestamp": `{"time_iso8601":"last tuesday","request_uri":"/x"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := New().Parse([]byte(body), receivedAt); err == nil {
				t.Fatal("must be dead-lettered rather than half-parsed")
			}
		})
	}
}

func TestHostFallsBackToServerName(t *testing.T) {
	body := `{"time_iso8601":"2026-08-19T12:00:00+00:00","cf_ray":"abc123","request_uri":"/x","server_name":"fallback.example.com","status":200}`
	e, err := New().Parse([]byte(body), receivedAt)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.Request.Host != "fallback.example.com" {
		t.Errorf("host should fall back to server_name, got %q", e.Request.Host)
	}
}

func TestRemoteAddrIsTheLastResort(t *testing.T) {
	// Behind Cloudflare, remote_addr is an edge address. It is used only when
	// nothing better is present.
	body := `{"time_iso8601":"2026-08-19T12:00:00+00:00","cf_ray":"abc123","request_uri":"/x","remote_addr":"172.16.0.5","cf_connecting_ip":"-","x_forwarded_for":"-","status":200}`
	e, err := New().Parse([]byte(body), receivedAt)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.Client.IP != "172.16.0.5" {
		t.Errorf("with nothing better available, remote_addr is used: got %q", e.Client.IP)
	}
}
