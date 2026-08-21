// Package f5asm parses F5 BIG-IP ASM key-value (HSL) log records.
//
// F5 is the weakest link in the correlation design. Logging an arbitrary request
// header such as CF-Ray is not confirmed in the official Request Logging profile
// documentation, and the field-standard approach is an iRule (verification item
// V2, unresolved). This parser therefore extracts CF-Ray from wherever it can —
// a dedicated field if the logging profile provides one, or the captured raw
// request text if an iRule wrote it there — and flags the record when neither
// works, so the degradation is visible rather than silent.
package f5asm

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/menta2k/siem-v2/backend/internal/correlate/keys"
	"github.com/menta2k/siem-v2/backend/internal/normalize"
	"github.com/menta2k/siem-v2/backend/internal/normalize/schema"
)

const parserVersion = "f5asm/1.1"

// kvRE matches key="value" pairs, allowing escaped quotes inside values.
var kvRE = regexp.MustCompile(`(\w+)="((?:[^"\\]|\\.)*)"`)

// cfRayRE finds a CF-Ray header inside captured raw request text. The ray id is
// followed by a colon and a datacentre code on the wire (e.g. "-FRA"), which is
// not part of the id Cloudflare logs, so it is deliberately excluded.
var cfRayRE = regexp.MustCompile(`(?i)CF-Ray:\s*([0-9a-f]+)`)

// hostRE finds the Host header inside the captured request text. ASM's KV log
// has no host field of its own — the vhost lives only in the raw request — so
// without this an F5 record (and any flow it stands alone in) has no host.
// The captured request keeps its CRLFs as literal \r\n escapes, so the header
// is delimited by literal backslashes, not real newlines. The value runs up to
// the next escape or real line break.
var hostRE = regexp.MustCompile(`(?i)(?:\\r\\n|\\n|[
]|^)Host:[ 	]*([^
\\]+)`)

type Parser struct{}

func New() *Parser { return &Parser{} }

func (p *Parser) Provider() schema.Provider { return schema.ProviderF5ASM }
func (p *Parser) Version() string           { return parserVersion }

func (p *Parser) Parse(raw []byte, receivedAt time.Time) (*schema.Event, error) {
	fields := parseKV(string(raw))
	if len(fields) == 0 {
		return nil, &normalize.ParseError{
			Provider: schema.ProviderF5ASM, Version: parserVersion,
			Reason: "no key=\"value\" pairs found; check the ASM logging profile format",
		}
	}

	supportID := fields["support_id"]
	if supportID == "" {
		return nil, &normalize.ParseError{
			Provider: schema.ProviderF5ASM, Version: parserVersion,
			Reason: "record has no support_id, so it cannot be deduplicated",
		}
	}

	eventTime, err := parseTime(fields["date_time"])
	if err != nil {
		return nil, &normalize.ParseError{
			Provider: schema.ProviderF5ASM, Version: parserVersion,
			Reason: "unparseable date_time", Err: err,
		}
	}

	status, _ := strconv.Atoi(fields["response_code"])
	e := &schema.Event{
		SchemaVersion: schema.Version,
		RawID:         "f5:" + supportID,
		EventID:       "f5:" + supportID,
		Provider:      schema.ProviderF5ASM,
		Dataset:       "asm",
		ParserVersion: parserVersion,
		// The support_id is F5's OWN reference — the one an operator quotes to F5
		// support and searches for in the ASM console. It is not a correlation
		// key (it means nothing to the other providers), but it is how an
		// investigation that starts in ASM finds its way here.
		VendorRequestID: supportID,
		EventTime:       eventTime,
		ReceivedAt:      receivedAt,
		Layer:           schema.LayerAppFirewall,
		Client: schema.Client{
			IP:      firstNonEmpty(fields["ip_client"], fields["x_forwarded_for_header_value"]),
			Country: strings.ToUpper(fields["geo_location"]),
		},
		Request: schema.Request{
			Host:   hostFrom(fields),
			Method: fields["method"],
			Path:   fields["uri"],
			Query:  fields["query_string"],
		},
		Response: schema.Response{Status: status},
	}
	if order, ok := e.Layer.Order(); ok {
		e.LayerOrderHint = order
	}

	// Shape from the captured request text, BEFORE masking. ASM ships the
	// full header block (unlike a configured Logpush subset), so its header
	// count is a real measurement.
	e.Shape = shapeFromRequest(fields["request"])

	e.Identifiers = extractIdentifiers(fields, e)
	e.Verdict = mapVerdict(fields)
	if !e.Verdict.Mapped {
		e.AddFlag(schema.FlagUnmappedValues)
	}
	normalize.ApplyTimeQuality(e)
	return e, nil
}

// shapeFromRequest measures the FULL header block of a captured request.
// Total request bytes are deliberately NOT claimed: the capture truncates
// bodies, and a lying floor understates exactly the ceiling the profiler
// exists to learn — absent is honest, small is not.
func shapeFromRequest(request string) *schema.Shape {
	if strings.TrimSpace(request) == "" {
		return nil
	}
	// CRLFs arrive escaped — singly (\r\n) or doubly (\\r\\n) depending on
	// how the KV value was unescaped upstream. Longest form first, so the
	// double escape never leaves a stray backslash behind to be miscounted as
	// a header line.
	text := strings.NewReplacer(
		`\\r\\n`, "\n", `\r\n`, "\n", `\\n`, "\n", `\n`, "\n", "\r\n", "\n",
	).Replace(request)
	lines := strings.Split(text, "\n")
	if len(lines) < 2 {
		return nil
	}
	var s *schema.Shape
	count, headerBytes := 0, 0
	for _, line := range lines[1:] { // lines[0] is the request line
		if strings.TrimSpace(line) == "" {
			break // the blank line ends the header block
		}
		count++
		headerBytes += len(line) + 2 // wire CRLF
		if name, value, ok := strings.Cut(line, ":"); ok && strings.EqualFold(strings.TrimSpace(name), "cookie") {
			s = normalize.ShapeFromCookieHeader(s, value)
		}
	}
	if count == 0 {
		return nil
	}
	if s == nil {
		s = &schema.Shape{}
	}
	s.HeaderCount = normalize.IntPtr(count)
	s.HeaderBytes = normalize.IntPtr(headerBytes)
	return s
}

// hostFrom resolves the request host from a dedicated field if the logging
// profile provides one, else the Host header scraped from the captured request.
func hostFrom(fields map[string]string) string {
	if h := firstNonEmpty(fields["host"], fields["virtual_server"]); h != "" {
		return h
	}
	if m := hostRE.FindStringSubmatch(fields["request"]); m != nil {
		return strings.TrimSpace(m[1])
	}
	return ""
}

// extractIdentifiers looks for CF-Ray in a dedicated field first, then in the
// captured raw request. The fallback exists because whether the logging profile
// can emit an arbitrary header is exactly what V2 has not established.
func extractIdentifiers(fields map[string]string, e *schema.Event) []string {
	rayValue := firstNonEmpty(fields["cf_ray"], fields["x_cf_ray"], fields["cf_ray_header"])
	if rayValue == "" {
		if m := cfRayRE.FindStringSubmatch(fields["request"]); m != nil {
			rayValue = m[1]
		}
	}
	if id, ok := keys.NewIdentifier(keys.NSRayID, rayValue); ok {
		e.RayID = id.Value
		e.CorrelationKeySource = schema.KeySourceRayID
		return []string{id.String()}
	}

	// No ray id anywhere. The record is still valuable — it carries the WAF
	// verdict — but it can only join heuristically. This is the V2 failure mode
	// made visible.
	e.CorrelationKeySource = schema.KeySourceNone
	e.AddFlag(schema.FlagNoCorrelationKey)
	return nil
}

// mapVerdict translates request_status plus the violation fields.
func mapVerdict(fields map[string]string) schema.Verdict {
	reason := map[string]any{
		"request_status": fields["request_status"],
		"violations":     fields["violations"],
		"sig_ids":        fields["sig_ids"],
		"sig_names":      fields["sig_names"],
		"attack_type":    fields["attack_type"],
		"severity":       fields["severity"],
		"support_id":     fields["support_id"],
	}

	sigID := firstField(fields["sig_ids"])
	sigName := firstField(fields["sig_names"])
	attackType := naToEmpty(fields["attack_type"])

	switch strings.ToLower(strings.TrimSpace(fields["request_status"])) {
	case "blocked":
		return schema.Verdict{
			Action: schema.ActionBlocked, Terminating: true,
			RuleID: sigID, RuleName: sigName, Category: attackType,
			Mapped: true, ReasonRaw: reason,
		}
	case "alerted":
		// Alerted means ASM detected but did not block — a logged decision, and
		// conflating it with a block would overstate what the WAF actually did.
		return schema.Verdict{
			Action: schema.ActionLogged,
			RuleID: sigID, RuleName: sigName, Category: attackType,
			Mapped: true, ReasonRaw: reason,
		}
	case "passed":
		return schema.Verdict{Action: schema.ActionAllowed, Mapped: true, ReasonRaw: reason}
	case "":
		return schema.Verdict{Action: schema.ActionUnknown, Mapped: false, ReasonRaw: reason}
	default:
		return schema.Verdict{
			Action: schema.ActionUnknown, Mapped: false,
			RuleID: sigID, RuleName: sigName, ReasonRaw: reason,
		}
	}
}

func parseKV(line string) map[string]string {
	out := map[string]string{}
	for _, m := range kvRE.FindAllStringSubmatch(line, -1) {
		out[m[1]] = m[2]
	}
	return out
}

func parseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	for _, layout := range []string{"2006-01-02 15:04:05", time.RFC3339, "2006-01-02T15:04:05Z0700"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, &normalize.ParseError{
		Provider: schema.ProviderF5ASM, Version: parserVersion,
		Reason: "date_time " + s + " matches no known layout",
	}
}

// firstField takes the first entry from a comma-separated ASM list field.
func firstField(s string) string {
	s = naToEmpty(s)
	if i := strings.IndexByte(s, ','); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}

// naToEmpty normalizes ASM's "N/A" placeholder. Carrying it forward would make
// "not applicable" look like a real attack type in the UI.
func naToEmpty(s string) string {
	if strings.EqualFold(strings.TrimSpace(s), "N/A") {
		return ""
	}
	return s
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" && !strings.EqualFold(v, "N/A") {
			return v
		}
	}
	return ""
}
