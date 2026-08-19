// Package datadome parses DataDome per-request decisions.
//
// DataDome arrives in two shapes and this parser handles both through one path:
//
//   - the pull export (/v1/logs/export), which is the primary source and carries
//     complete decisions;
//   - the x-datadome-* headers a Cloudflare Worker injects, captured into the
//     Logpush record via transformed_request_fields.
//
// Aliasing the field names rather than writing two parsers is deliberate: the two
// shapes describe the same decision, and keeping one mapping means a change to
// the verdict vocabulary cannot drift between them (research.md R3).
package datadome

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/menta2k/siem-v2/backend/internal/correlate/keys"
	"github.com/menta2k/siem-v2/backend/internal/normalize"
	"github.com/menta2k/siem-v2/backend/internal/normalize/schema"
)

const parserVersion = "datadome/1.0"

type Parser struct{}

func New() *Parser { return &Parser{} }

func (p *Parser) Provider() schema.Provider { return schema.ProviderDataDome }
func (p *Parser) Version() string           { return parserVersion }

// actionMap translates DataDome's decision vocabulary. As everywhere, an
// unrecognized value is surfaced rather than guessed (FR-014).
var actionMap = map[string]schema.Action{
	"allow":        schema.ActionAllowed,
	"authorize":    schema.ActionAllowed,
	"block":        schema.ActionBlocked,
	"hard_block":   schema.ActionBlocked,
	"captcha":      schema.ActionChallenged,
	"interstitial": schema.ActionChallenged,
	"challenge":    schema.ActionChallenged,
}

// Parse converts one DataDome record, in either shape, into a normalized event.
func (p *Parser) Parse(raw []byte, receivedAt time.Time) (*schema.Event, error) {
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, &normalize.ParseError{
			Provider: schema.ProviderDataDome, Version: parserVersion,
			Reason: "malformed JSON", Err: err,
		}
	}

	requestID := asString(firstOf(fields, "requestid", "x-datadome-requestid"))
	if requestID == "" {
		return nil, &normalize.ParseError{
			Provider: schema.ProviderDataDome, Version: parserVersion,
			Reason: "record has no requestid, so it cannot be correlated",
		}
	}

	eventTime, err := parseTime(firstOf(fields, "timestamp", "date"))
	if err != nil {
		return nil, &normalize.ParseError{
			Provider: schema.ProviderDataDome, Version: parserVersion,
			Reason: "unparseable timestamp", Err: err,
		}
	}

	uri := asString(firstOf(fields, "uri", "url"))
	path, query := splitURI(uri)

	e := &schema.Event{
		SchemaVersion:        schema.Version,
		RawID:                "dd:" + requestID,
		EventID:              "dd:" + requestID,
		Provider:             schema.ProviderDataDome,
		Dataset:              "logs_export",
		ParserVersion:        parserVersion,
		VendorRequestID:      requestID,
		CorrelationKeySource: schema.KeySourceVendorRequestID,
		EventTime:            eventTime,
		ReceivedAt:           receivedAt,
		Layer:                schema.LayerBotManagement,
		Client: schema.Client{
			IP:        asString(firstOf(fields, "ip", "client_ip")),
			ASN:       asInt(firstOf(fields, "asn")),
			Country:   strings.ToUpper(asString(firstOf(fields, "country"))),
			UserAgent: asString(firstOf(fields, "ua", "user_agent")),
		},
		Request: schema.Request{
			Method: asString(firstOf(fields, "method")),
			Host:   asString(firstOf(fields, "host")),
			Path:   path, Query: query,
		},
	}
	if order, ok := e.Layer.Order(); ok {
		e.LayerOrderHint = order
	}
	if id, ok := keys.NewIdentifier(keys.NSDataDome, requestID); ok {
		e.Identifiers = []string{id.String()}
	}

	e.Verdict = mapVerdict(fields)
	e.Bot = mapBot(fields, requestID)
	if !e.Verdict.Mapped {
		e.AddFlag(schema.FlagUnmappedValues)
	}
	normalize.ApplyTimeQuality(e)
	return e, nil
}

func mapVerdict(fields map[string]any) schema.Verdict {
	rawAction := strings.ToLower(strings.TrimSpace(
		asString(firstOf(fields, "action", "x-datadome-action", "x-datadome-traffic-rule-response"))))

	reason := map[string]any{
		"action":   rawAction,
		"ruletype": asString(firstOf(fields, "ruletype", "x-datadome-ruletype")),
		"botname":  asString(firstOf(fields, "botname", "x-datadome-botname")),
	}
	score := asFloatPtr(firstOf(fields, "botscore", "x-datadome-botscore", "x-datadome-score"))

	if rawAction == "" {
		return schema.Verdict{Action: schema.ActionUnknown, Mapped: false, Score: score, ReasonRaw: reason}
	}
	mapped, ok := actionMap[rawAction]
	if !ok {
		return schema.Verdict{Action: schema.ActionUnknown, Mapped: false, Score: score, ReasonRaw: reason}
	}
	return schema.Verdict{
		Action:      mapped,
		Terminating: mapped.Terminal(),
		Category:    asString(firstOf(fields, "ruletype", "x-datadome-ruletype")),
		RuleName:    asString(firstOf(fields, "botname", "x-datadome-botname")),
		Score:       score,
		Mapped:      true,
		ReasonRaw:   reason,
	}
}

func mapBot(fields map[string]any, requestID string) *schema.Bot {
	return &schema.Bot{
		DataDomePresent:   requestID != "",
		DataDomeIsBot:     asString(firstOf(fields, "isbot", "x-datadome-isbot")),
		DataDomeBotName:   asString(firstOf(fields, "botname", "x-datadome-botname")),
		DataDomeRuleType:  asString(firstOf(fields, "ruletype", "x-datadome-ruletype")),
		DataDomeAction:    asString(firstOf(fields, "action", "x-datadome-traffic-rule-response")),
		DataDomeScore:     asFloatPtr(firstOf(fields, "botscore", "x-datadome-botscore")),
		DataDomeRiskScore: asFloatPtr(firstOf(fields, "riskscore", "x-datadome-riskscore")),
	}
}

// firstOf returns the first present, non-empty value among the given keys. This
// is what lets one mapping serve both the pull-export and header field shapes.
func firstOf(fields map[string]any, names ...string) any {
	for _, n := range names {
		if v, ok := fields[n]; ok && v != nil && v != "" {
			return v
		}
		// Header names may arrive with different casing than configured.
		for k, v := range fields {
			if strings.EqualFold(k, n) && v != nil && v != "" {
				return v
			}
		}
	}
	return nil
}

func asString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		if t {
			return "1"
		}
		return "0"
	case nil:
		return ""
	default:
		return ""
	}
}

func asInt(v any) int {
	switch t := v.(type) {
	case float64:
		return int(t)
	case string:
		n, _ := strconv.Atoi(t)
		return n
	default:
		return 0
	}
}

func asFloatPtr(v any) *float64 {
	switch t := v.(type) {
	case float64:
		return &t
	case string:
		f, err := strconv.ParseFloat(t, 64)
		if err != nil {
			return nil
		}
		return &f
	default:
		return nil
	}
}

func parseTime(v any) (time.Time, error) {
	s := asString(v)
	if s == "" {
		return time.Time{}, nil
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return time.UnixMilli(n).UTC(), nil
	}
	return time.Time{}, &normalize.ParseError{
		Provider: schema.ProviderDataDome, Version: parserVersion,
		Reason: "timestamp " + s + " matches no known layout",
	}
}

func splitURI(uri string) (path, query string) {
	if i := strings.IndexByte(uri, '?'); i >= 0 {
		return uri[:i], uri[i+1:]
	}
	return uri, ""
}
