// Package cloudflare parses Cloudflare Logpush http_requests records.
//
// This parser carries more weight than the others for one reason: the Cloudflare
// record is the only one that knows two identifier spaces. It has the Ray ID,
// and — when Logpush custom fields are configured — the DataDome request id from
// the Worker's x-datadome-* headers. That makes it the bridge that lets a
// DataDome record join an nginx line at exact tier (research.md R3, R11a).
package cloudflare

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/menta2k/siem-v2/backend/internal/correlate/keys"
	"github.com/menta2k/siem-v2/backend/internal/normalize"
	"github.com/menta2k/siem-v2/backend/internal/normalize/schema"
)

const parserVersion = "cloudflare/1.0"

// Parser normalizes Cloudflare Logpush records.
type Parser struct{}

func New() *Parser { return &Parser{} }

func (p *Parser) Provider() schema.Provider { return schema.ProviderCloudflare }
func (p *Parser) Version() string           { return parserVersion }

// record mirrors the Logpush http_requests fields we consume. Both the current
// Security* family and the legacy WAFAction/FirewallMatches* family are declared
// because which one a zone populates depends on its plan and age, and that has
// not been verified for this deployment (V5). Parsing both is cheaper than
// guessing wrong.
type record struct {
	RayID string `json:"RayID"`

	// Timestamps are either RFC3339 strings or nanosecond integers depending on
	// the job's output_options.timestamp_format. json.RawMessage lets us accept
	// whichever arrives rather than failing the whole record on a format we did
	// not expect.
	EdgeStartTimestamp json.RawMessage `json:"EdgeStartTimestamp"`
	EdgeEndTimestamp   json.RawMessage `json:"EdgeEndTimestamp"`

	ClientIP               string `json:"ClientIP"`
	ClientRequestHost      string `json:"ClientRequestHost"`
	ClientRequestURI       string `json:"ClientRequestURI"`
	ClientRequestMethod    string `json:"ClientRequestMethod"`
	ClientRequestUserAgent string `json:"ClientRequestUserAgent"`
	ClientCountry          string `json:"ClientCountry"`
	ClientASN              int    `json:"ClientASN"`
	EdgeResponseStatus     int    `json:"EdgeResponseStatus"`
	BotScore               *int   `json:"BotScore"`

	// Current security fields.
	SecurityAction          string   `json:"SecurityAction"`
	SecurityRuleID          string   `json:"SecurityRuleID"`
	SecurityRuleDescription string   `json:"SecurityRuleDescription"`
	SecurityActions         []string `json:"SecurityActions"`
	SecuritySources         []string `json:"SecuritySources"`
	SecurityRuleIDs         []string `json:"SecurityRuleIDs"`

	// Legacy security fields.
	WAFAction              *int     `json:"WAFAction"`
	WAFRuleID              string   `json:"WAFRuleID"`
	FirewallMatchesActions []string `json:"FirewallMatchesActions"`
	FirewallMatchesSources []string `json:"FirewallMatchesSources"`
	FirewallMatchesRuleIDs []string `json:"FirewallMatchesRuleIDs"`

	// Cloudflare's ML attack scores. 1 means "almost certainly an attack" and 99
	// means "almost certainly clean" — the scale runs the opposite way to a bot
	// score, which is a trap worth naming rather than discovering later.
	WAFAttackScore     *int   `json:"WAFAttackScore"`
	WAFSQLiAttackScore *int   `json:"WAFSQLiAttackScore"`
	WAFXSSAttackScore  *int   `json:"WAFXSSAttackScore"`
	WAFRCEAttackScore  *int   `json:"WAFRCEAttackScore"`
	WAFFlags           string `json:"WAFFlags"`
	WAFMatchedVar      string `json:"WAFMatchedVar"`

	MatchedRules []map[string]any `json:"MatchedRules"`

	BotScoreSrc string   `json:"BotScoreSrc"`
	BotTags     []string `json:"BotTags"`
	JA3Hash     string   `json:"JA3Hash"`
	JA4         string   `json:"JA4"`

	ZoneName     string `json:"ZoneName"`
	EdgeColoCode string `json:"EdgeColoCode"`
	ParentRayID  string `json:"ParentRayID"`
	WorkerStatus string `json:"WorkerStatus"`

	// Custom-field captures. A Worker-injected header appears in RESPONSE
	// headers, not request headers — the Worker sets it on the way out. Reading
	// only RequestHeaders is why the DataDome verdict would never be found.
	RequestHeaders  map[string]string `json:"RequestHeaders"`
	ResponseHeaders map[string]string `json:"ResponseHeaders"`
}

// Parse converts one NDJSON line into a normalized event.
func (p *Parser) Parse(raw []byte, receivedAt time.Time) (*schema.Event, error) {
	var r record
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, &normalize.ParseError{
			Provider: schema.ProviderCloudflare, Version: parserVersion,
			Reason: "malformed JSON", Err: err,
		}
	}
	if strings.TrimSpace(r.RayID) == "" {
		return nil, &normalize.ParseError{
			Provider: schema.ProviderCloudflare, Version: parserVersion,
			Reason: "record has no RayID, so it cannot be correlated or deduplicated",
		}
	}

	// A Worker's call to DataDome is a SUBREQUEST, not a visitor request. It
	// becomes the bot-management verdict on its parent, and must never be
	// presented as an edge event of its own — doing so would double-count
	// traffic and put a POST to api-cloudflare.datadome.co in front of analysts
	// as if a client had made it.
	if isDataDomeCall(r) {
		return deriveDataDome(r, receivedAt), nil
	}

	start, err := parseTimestamp(r.EdgeStartTimestamp)
	if err != nil {
		return nil, &normalize.ParseError{
			Provider: schema.ProviderCloudflare, Version: parserVersion,
			Reason: "unparseable EdgeStartTimestamp (check the job's timestamp_format)", Err: err,
		}
	}

	path, query := splitURI(r.ClientRequestURI)

	e := &schema.Event{
		SchemaVersion: schema.Version,
		RawID:         "cf:" + r.RayID,
		EventID:       "cf:" + r.RayID,
		Provider:      schema.ProviderCloudflare,
		Dataset:       "http_requests",
		ParserVersion: parserVersion,
		RayID:         r.RayID,
		EventTime:     start,
		ReceivedAt:    receivedAt,
		Layer:         schema.LayerEdge,
		Client: schema.Client{
			IP: r.ClientIP, ASN: r.ClientASN,
			Country: strings.ToUpper(r.ClientCountry), UserAgent: r.ClientRequestUserAgent,
		},
		Request: schema.Request{
			Method: r.ClientRequestMethod, Host: r.ClientRequestHost,
			Path: path, Query: query, Headers: r.RequestHeaders,
		},
		Response: schema.Response{Status: r.EdgeResponseStatus},
	}
	if order, ok := e.Layer.Order(); ok {
		e.LayerOrderHint = order
	}
	if end, err := parseTimestamp(r.EdgeEndTimestamp); err == nil && !end.IsZero() && !start.IsZero() {
		e.Response.DurationMS = float64(end.Sub(start).Microseconds()) / 1000.0
	}

	e.Identifiers = identifiers(r)
	e.CorrelationKeySource = schema.KeySourceRayID
	e.Verdict = mapVerdict(r)
	e.Bot = mapBot(r)
	if e.Bot != nil && !e.Bot.DataDomePresent {
		// The absence of DataDome fields is a configuration fault worth surfacing,
		// not evidence that no bot decision was made (research.md R3).
		e.AddFlag(schema.FlagDataDomeFieldsAbsent)
	}
	if !e.Verdict.Mapped {
		e.AddFlag(schema.FlagUnmappedValues)
	}
	normalize.ApplyTimeQuality(e)
	return e, nil
}

// identifiers returns every per-request id this record carries.
//
// Returning more than one is the entire point, and on Cloudflare there are
// genuinely two.
//
// When a Worker is in play, one visitor request produces several Cloudflare rows:
// the Worker's fetch to the origin gets its own ray, and its call to DataDome
// gets another, both carrying the VISITOR's ray as ParentRayID. Origin-side logs
// (nginx, F5) see the fetch's own ray, while the DataDome verdict is keyed on the
// parent. A record contributing both is therefore the bridge that joins the origin
// layers to the bot layer — through the existing exact tier, with no time window
// and no heuristic (FR-072f).
func identifiers(r record) []string {
	var ids []string
	if id, ok := keys.NewIdentifier(keys.NSRayID, r.RayID); ok {
		ids = append(ids, id.String())
	}
	// The parent ray, when this record is a subrequest. parentRay() filters the
	// literal "00" Cloudflare writes for top-level requests, which would otherwise
	// key the entire tenant onto one identifier.
	if parent := parentRay(r); parent != "" {
		if id, ok := keys.NewIdentifier(keys.NSRayID, parent); ok {
			ids = append(ids, id.String())
		}
	}
	// Header lookup is case-insensitive: Cloudflare requires lower-case names in
	// the custom-fields config, but nothing guarantees the delivered map preserves
	// that, and a case mismatch here would silently drop the bridge.
	if v := headerLookup(r, "x-datadome-requestid"); v != "" {
		if id, ok := keys.NewIdentifier(keys.NSDataDome, v); ok {
			ids = append(ids, id.String())
		}
	}
	return ids
}

// headerLookup searches the captured headers case-insensitively.
//
// Both request and response captures are searched because a Worker-injected
// header lands in the RESPONSE headers: the Worker runs on the way out. This was
// established from real records — searching only RequestHeaders silently found
// nothing while everything else looked correct.
func headerLookup(r record, name string) string {
	for _, headers := range []map[string]string{r.ResponseHeaders, r.RequestHeaders} {
		if headers == nil {
			continue
		}
		if v, ok := headers[name]; ok && v != "" {
			return v
		}
		for k, v := range headers {
			if strings.EqualFold(k, name) && v != "" {
				return v
			}
		}
	}
	return ""
}

// splitURI separates the path from the query string. Cloudflare's
// ClientRequestURI includes both.
func splitURI(uri string) (path, query string) {
	if i := strings.IndexByte(uri, '?'); i >= 0 {
		return uri[:i], uri[i+1:]
	}
	return uri, ""
}

// parseTimestamp accepts both timestamp_format variants. The API default is
// unixnano and the dashboard default is rfc3339, so a parser that handles only
// one will silently misread every record from a job configured the other way.
func parseTimestamp(raw json.RawMessage) (time.Time, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return time.Time{}, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		if s == "" {
			return time.Time{}, nil
		}
		return time.Parse(time.RFC3339Nano, s)
	}
	var n int64
	if err := json.Unmarshal(raw, &n); err == nil {
		if n == 0 {
			return time.Time{}, nil
		}
		return time.Unix(0, n).UTC(), nil
	}
	return time.Time{}, fmt.Errorf("timestamp %s is neither RFC3339 string nor epoch nanoseconds", string(raw))
}
