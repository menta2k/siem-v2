// Package nginx parses nginx access logs in the SIEM JSON log format.
//
// JSON, not the combined text format. Real deployments configure a JSON
// log_format because the combined format cannot carry the extra fields this
// system needs — cf_ray above all — without positional parsing that breaks the
// moment someone adds a field.
//
// The cf_ray field is what makes the join to Cloudflare exact rather than
// heuristic (research.md R11).
package nginx

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/menta2k/siem-v2/backend/internal/correlate/keys"
	"github.com/menta2k/siem-v2/backend/internal/normalize"
	"github.com/menta2k/siem-v2/backend/internal/normalize/schema"
)

const parserVersion = "nginx/2.0"

// record mirrors the JSON log_format this system expects nginx to emit.
type record struct {
	TimeISO8601    string `json:"time_iso8601"`
	CFRay          string `json:"cf_ray"`
	CFConnectingIP string `json:"cf_connecting_ip"`
	XForwardedFor  string `json:"x_forwarded_for"`
	RemoteAddr     string `json:"remote_addr"`
	Host           string `json:"host"`
	ServerName     string `json:"server_name"`
	RequestMethod  string `json:"request_method"`
	RequestURI     string `json:"request_uri"`
	ServerProtocol string `json:"server_protocol"`
	Scheme         string `json:"scheme"`
	Status         any    `json:"status"`
	BodyBytesSent  any    `json:"body_bytes_sent"`
	RequestLength  any    `json:"request_length"`
	RequestTime    any    `json:"request_time"`
	UpstreamAddr   string `json:"upstream_addr"`
	UpstreamStatus any    `json:"upstream_status"`
	UpstreamTime   any    `json:"upstream_response_time"`
	UserAgent      string `json:"user_agent"`
	Referer        string `json:"referer"`
}

type Parser struct{}

func New() *Parser { return &Parser{} }

func (p *Parser) Provider() schema.Provider { return schema.ProviderNginx }
func (p *Parser) Version() string           { return parserVersion }

func (p *Parser) Parse(raw []byte, receivedAt time.Time) (*schema.Event, error) {
	var r record
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, &normalize.ParseError{
			Provider: schema.ProviderNginx, Version: parserVersion,
			Reason: "not JSON; nginx must use the documented JSON log_format", Err: err,
		}
	}
	if r.TimeISO8601 == "" && r.RequestURI == "" {
		return nil, &normalize.ParseError{
			Provider: schema.ProviderNginx, Version: parserVersion,
			Reason: "record has neither time_iso8601 nor request_uri; log_format does not match",
		}
	}

	eventTime, err := parseTime(r.TimeISO8601)
	if err != nil {
		return nil, &normalize.ParseError{
			Provider: schema.ProviderNginx, Version: parserVersion,
			Reason: "unparseable time_iso8601", Err: err,
		}
	}

	path, query := splitURI(r.RequestURI)
	rawID := "ngx:" + contentHash(raw)

	e := &schema.Event{
		SchemaVersion: schema.Version,
		RawID:         rawID,
		EventID:       rawID,
		Provider:      schema.ProviderNginx,
		Dataset:       "access",
		ParserVersion: parserVersion,
		EventTime:     eventTime,
		ReceivedAt:    receivedAt,
		Layer:         schema.LayerOrigin,
		Client: schema.Client{
			// The true client, in preference order. remote_addr is the LAST
			// resort: behind Cloudflare it is an edge address, and reporting it
			// as the client would attribute every request to the CDN.
			IP:        clientIP(r),
			UserAgent: emptyIfDash(r.UserAgent),
		},
		Request: schema.Request{
			Method: r.RequestMethod, Host: firstNonEmpty(r.Host, r.ServerName),
			Path: path, Query: query, HTTPVersion: r.ServerProtocol,
		},
		Response: schema.Response{
			Status: asInt(r.Status),
			Bytes:  int64(asInt(r.BodyBytesSent)),
		},
	}
	if order, ok := e.Layer.Order(); ok {
		e.LayerOrderHint = order
	}
	if seconds := asFloat(r.RequestTime); seconds > 0 {
		e.Response.DurationMS = seconds * 1000
	}

	if id, ok := keys.NewIdentifier(keys.NSRayID, NormalizeRayID(r.CFRay)); ok {
		e.Identifiers = []string{id.String()}
		e.RayID = id.Value
		e.CorrelationKeySource = schema.KeySourceRayID
	} else {
		e.CorrelationKeySource = schema.KeySourceNone
		e.AddFlag(schema.FlagNoCorrelationKey)
	}

	e.Verdict = schema.Verdict{
		Action:      statusToAction(e.Response.Status),
		Terminating: false,
		Mapped:      true,
		ReasonRaw: map[string]any{
			"status": e.Response.Status, "upstream_status": asInt(r.UpstreamStatus),
		},
	}

	normalize.ApplyTimeQuality(e)
	return e, nil
}

// NormalizeRayID strips the datacentre suffix nginx receives on the wire.
//
// Cloudflare sends the CF-Ray header as "<id>-<COLO>" (for example
// "a2d6ea0f6813ccd4-DXB") but logs only the bare id in Logpush. Keeping the
// suffix here would mean every nginx record failed to join its Cloudflare
// record, silently pushing the whole origin layer into the heuristic tier —
// correlation would still "work", just far worse, with nothing to indicate why.
func NormalizeRayID(rayID string) string {
	v := strings.TrimSpace(rayID)
	if v == "" || v == "-" {
		return ""
	}
	if i := strings.IndexByte(v, '-'); i > 0 {
		return v[:i]
	}
	return v
}

// clientIP resolves the true client address.
func clientIP(r record) string {
	if ip := strings.TrimSpace(r.CFConnectingIP); ip != "" && ip != "-" {
		return ip
	}
	// X-Forwarded-For is a list; the left-most entry is the original client.
	if xff := strings.TrimSpace(r.XForwardedFor); xff != "" && xff != "-" {
		if i := strings.IndexByte(xff, ','); i > 0 {
			return strings.TrimSpace(xff[:i])
		}
		return xff
	}
	return emptyIfDash(r.RemoteAddr)
}

func statusToAction(status int) schema.Action {
	switch {
	case status == 429:
		return schema.ActionRateLimited
	case status == 403 || status == 401:
		return schema.ActionBlocked
	default:
		return schema.ActionAllowed
	}
}

func parseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05-07:00"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, &normalize.ParseError{
		Provider: schema.ProviderNginx, Version: parserVersion,
		Reason: "time_iso8601 " + s + " matches no known layout",
	}
}

func splitURI(uri string) (path, query string) {
	if i := strings.IndexByte(uri, '?'); i >= 0 {
		return uri[:i], uri[i+1:]
	}
	return uri, ""
}

// asInt accepts both the numeric and string encodings nginx may emit: a JSON
// log_format writes numbers unquoted, but some builds and some fields quote
// them, and a parser that handled only one would silently read zero.
func asInt(v any) int {
	switch t := v.(type) {
	case float64:
		return int(t)
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(t))
		return n
	default:
		return 0
	}
}

func asFloat(v any) float64 {
	switch t := v.(type) {
	case float64:
		return t
	case string:
		f, _ := strconv.ParseFloat(strings.TrimSpace(t), 64)
		return f
	default:
		return 0
	}
}

func emptyIfDash(s string) string {
	if s == "-" {
		return ""
	}
	return s
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" && v != "-" {
			return v
		}
	}
	return ""
}

func contentHash(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:12])
}
