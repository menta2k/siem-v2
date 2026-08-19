package victorialogs

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// FlowSearch is the typed, enumerated search input.
//
// Every field here is a named, typed parameter — there is deliberately no
// free-text query field. That absence is the security property: a caller cannot
// express a cross-tenant or injected query because there is no syntax in which
// to write one (FR-074b, R8).
type FlowSearch struct {
	From         time.Time
	To           time.Time
	ClientIP     string
	Host         string
	PathPrefix   string
	Method       string
	Status       int
	Action       string
	Layer        string
	RuleID       string
	Country      string
	UserAgentSub string
	Provider     string
	Completeness string

	// RayID is the definitive identifier. Two providers reporting the same ray
	// are describing the same request whatever their clocks say, so this is the
	// fastest route from "one layer saw this" to "what did the others see".
	RayID string
	// VendorRequestID matches a provider's OWN reference — F5's support_id above
	// all. Distinct from RayID, which every provider shares: this is the id one
	// console shows, and it is how an investigation that began there gets here.
	VendorRequestID string
	// CorrelationMethod filters by join tier, so an analyst can review exactly
	// the flows whose assembly is uncertain.
	CorrelationMethod string
	// Bridged selects flows that were only joined because a record carried two
	// identifier spaces — the ones that depend on Logpush custom fields.
	Bridged *bool
	ASN     int
	// MinLayers finds under-covered flows: "show me requests where the WAF never
	// reported" is a collection question, not a security one, and it needs asking.
	MinLayers int
	MaxLayers int
	// HasQualityFlag surfaces flows carrying a specific data-quality condition.
	HasQualityFlag string

	Limit int
}

// safeValue matches values we are willing to embed in a query at all.
//
// This is a whitelist rather than an escape routine on purpose: escaping is a
// game of finding every metacharacter, while a whitelist fails closed on
// anything unanticipated.
var safeValue = regexp.MustCompile(`^[A-Za-z0-9 ._:/@+-]{0,256}$`)

// ErrUnsafeValue is returned when a search value contains characters that could
// alter query structure.
type ErrUnsafeValue struct{ Field, Value string }

func (e *ErrUnsafeValue) Error() string {
	return fmt.Sprintf("search value for %q contains unsupported characters", e.Field)
}

// BuildFlowQuery compiles a typed search into LogsQL, scoped to one tenant.
//
// The record_kind and tenant filters are added unconditionally and first, so
// every generated query is scoped whether or not the caller supplied anything.
func BuildFlowQuery(tenant string, s FlowSearch) (string, error) {
	if !safeValue.MatchString(tenant) || tenant == "" {
		return "", &ErrUnsafeValue{Field: "tenant", Value: tenant}
	}

	var parts []string
	// Stream-level scoping first: cheapest filter, and it is not optional.
	parts = append(parts, fmt.Sprintf(`{tenant=%s,record_kind=%s}`, quote(tenant), quote(string(KindFlow))))

	if !s.From.IsZero() && !s.To.IsZero() {
		parts = append(parts, fmt.Sprintf("_time:[%s, %s]",
			s.From.UTC().Format(time.RFC3339), s.To.UTC().Format(time.RFC3339)))
	}

	exact := []struct {
		field string
		value string
	}{
		{"client_ip", s.ClientIP},
		{"host", s.Host},
		{"method", strings.ToUpper(s.Method)},
		{"effective_outcome", s.Action},
		{"terminating_layer", s.Layer},
		{"rule_id", s.RuleID},
		{"country", strings.ToUpper(s.Country)},
		{"completeness", s.Completeness},
		{"ray_id", s.RayID},
		{"correlation_method", s.CorrelationMethod},
	}
	for _, f := range exact {
		if f.value == "" {
			continue
		}
		if !safeValue.MatchString(f.value) {
			return "", &ErrUnsafeValue{Field: f.field, Value: f.value}
		}
		parts = append(parts, fmt.Sprintf("%s:=%s", f.field, quote(f.value)))
	}

	if s.Status > 0 {
		parts = append(parts, "status:="+strconv.Itoa(s.Status))
	}
	if s.ASN > 0 {
		parts = append(parts, "asn:="+strconv.Itoa(s.ASN))
	}
	if s.Bridged != nil {
		parts = append(parts, fmt.Sprintf("bridged:=%t", *s.Bridged))
	}
	if s.MinLayers > 0 {
		parts = append(parts, fmt.Sprintf("layer_count:>=%d", s.MinLayers))
	}
	if s.MaxLayers > 0 {
		parts = append(parts, fmt.Sprintf("layer_count:<=%d", s.MaxLayers))
	}
	if s.HasQualityFlag != "" {
		if !safeValue.MatchString(s.HasQualityFlag) {
			return "", &ErrUnsafeValue{Field: "quality_flag", Value: s.HasQualityFlag}
		}
		parts = append(parts, fmt.Sprintf("data_quality_flags:%s", quote(s.HasQualityFlag)))
	}
	// Word match, not exact match: a flow carries several vendor references in one
	// field, so the filter must find one among them rather than equal the whole
	// set.
	// The flow record's own "provider" field is the constant "correlated";
	// participation lives in the space-joined providers list, word-matched
	// exactly like vendor_request_ids.
	if s.Provider != "" {
		if !safeValue.MatchString(s.Provider) {
			return "", &ErrUnsafeValue{Field: "provider", Value: s.Provider}
		}
		parts = append(parts, fmt.Sprintf("providers:%s", quote(s.Provider)))
	}
	if s.VendorRequestID != "" {
		if !safeValue.MatchString(s.VendorRequestID) {
			return "", &ErrUnsafeValue{Field: "support_id", Value: s.VendorRequestID}
		}
		parts = append(parts, fmt.Sprintf("vendor_request_ids:%s", quote(s.VendorRequestID)))
	}
	if s.PathPrefix != "" {
		if !safeValue.MatchString(s.PathPrefix) {
			return "", &ErrUnsafeValue{Field: "path", Value: s.PathPrefix}
		}
		parts = append(parts, fmt.Sprintf("path:%s*", quote(s.PathPrefix)))
	}
	if s.UserAgentSub != "" {
		if !safeValue.MatchString(s.UserAgentSub) {
			return "", &ErrUnsafeValue{Field: "user_agent", Value: s.UserAgentSub}
		}
		parts = append(parts, fmt.Sprintf("user_agent:~%s", quote(s.UserAgentSub)))
	}

	return strings.Join(parts, " "), nil
}

// BuildFlowByIDQuery fetches one flow, tenant-scoped.
func BuildFlowByIDQuery(tenant, flowID string) (string, error) {
	if !safeValue.MatchString(tenant) || tenant == "" {
		return "", &ErrUnsafeValue{Field: "tenant", Value: tenant}
	}
	if !safeValue.MatchString(flowID) || flowID == "" {
		return "", &ErrUnsafeValue{Field: "flow_id", Value: flowID}
	}
	return fmt.Sprintf(`{tenant=%s,record_kind=%s} flow_id:=%s`,
		quote(tenant), quote(string(KindFlow)), quote(flowID)), nil
}

// quote wraps a value in LogsQL double quotes, escaping backslashes and quotes.
// Values reaching here have already passed the whitelist; this is defence in
// depth rather than the primary control.
func quote(v string) string {
	escaped := strings.ReplaceAll(v, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	return `"` + escaped + `"`
}

// BuildRawByIDQuery fetches one raw record, tenant-scoped.
func BuildRawByIDQuery(tenant, rawID string) (string, error) {
	if !safeValue.MatchString(tenant) || tenant == "" {
		return "", &ErrUnsafeValue{Field: "tenant", Value: tenant}
	}
	if !safeValue.MatchString(rawID) || rawID == "" {
		return "", &ErrUnsafeValue{Field: "raw_id", Value: rawID}
	}
	return fmt.Sprintf(`{tenant=%s,record_kind=%s} raw_id:=%s`,
		quote(tenant), quote(string(KindRaw)), quote(rawID)), nil
}
