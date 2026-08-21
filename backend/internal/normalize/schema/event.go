// Package schema defines the common event schema that every provider record is
// mapped to.
//
// This is the most important contract in the project (Constitution Principle II).
// Changes are additive only: removing a field or changing its type is breaking
// and requires a migration plan plus a re-parse or dual-write of existing data.
// The authoritative JSON Schema lives at
// specs/001-waf-log-correlation/contracts/normalized-event.schema.json.
package schema

import "time"

// Version is the schema version stamped on every event. Bump the minor version
// for additive changes; a major bump means existing stored data no longer parses
// with this package and needs migration.
//
// 1.1: added the optional request Shape (structural facts captured before
// masking, for the traffic profiler). Additive only.
const Version = "1.1"

// Provider identifies the system that produced a record.
//
// DataDome is a first-class provider even though part of its data arrives inside
// the Cloudflare record: it also has its own pull feed, and both shapes normalize
// to the same provider (research.md R3).
type Provider string

const (
	ProviderCloudflare Provider = "cloudflare"
	ProviderDataDome   Provider = "datadome"
	ProviderF5ASM      Provider = "f5asm"
	ProviderNginx      Provider = "nginx"
)

// Layer is the position in the request path. Ordering within a flow derives from
// this, not from timestamps, because provider clocks disagree (FR-017).
type Layer string

const (
	LayerEdge          Layer = "edge"
	LayerBotManagement Layer = "bot_management"
	LayerAppFirewall   Layer = "app_firewall"
	LayerOrigin        Layer = "origin"
)

// layerOrder is the causal position of each layer in the request path. It is the
// ordering source of truth: a request reaches the edge before the origin
// regardless of what the two systems' clocks claim.
var layerOrder = map[Layer]int{
	LayerEdge:          0,
	LayerBotManagement: 1,
	LayerAppFirewall:   2,
	LayerOrigin:        3,
}

// Order returns the causal position of a layer and whether it is a known layer.
func (l Layer) Order() (int, bool) {
	o, ok := layerOrder[l]
	return o, ok
}

// Action is the normalized verdict vocabulary (FR-025). Provider-specific
// decisions map onto exactly these values; anything unrecognized becomes
// ActionUnknown with Verdict.Mapped false rather than being coerced (FR-014).
type Action string

const (
	ActionAllowed         Action = "allowed"
	ActionLogged          Action = "logged"
	ActionRateLimited     Action = "rate_limited"
	ActionChallenged      Action = "challenged"
	ActionChallengePassed Action = "challenge_passed"
	ActionChallengeFailed Action = "challenge_failed"
	ActionBlocked         Action = "blocked"
	ActionUnknown         Action = "unknown"
)

// Terminal reports whether an action ends the request at that layer. Used to
// resolve which layer actually terminated a flow (FR-027).
func (a Action) Terminal() bool {
	switch a {
	case ActionBlocked, ActionChallengeFailed, ActionRateLimited:
		return true
	default:
		return false
	}
}

// TimeQuality flags timestamps we do not trust. Implausible times are flagged,
// never silently corrected (FR-013).
type TimeQuality string

const (
	TimeQualityOK          TimeQuality = "ok"
	TimeQualitySkewed      TimeQuality = "skewed"
	TimeQualityImplausible TimeQuality = "implausible"
)

// QualityFlag marks a condition that affects how a record or flow should be read.
// These surface in the UI so a partial view is never mistaken for a complete one
// (FR-070).
type QualityFlag string

const (
	FlagClockSkew            QualityFlag = "clock_skew"
	FlagImplausibleTime      QualityFlag = "implausible_time"
	FlagBodyTruncated        QualityFlag = "body_truncated"
	FlagFieldsMasked         QualityFlag = "fields_masked"
	FlagUnmappedValues       QualityFlag = "unmapped_values"
	FlagHeuristicCorrelation QualityFlag = "heuristic_correlation"
	FlagBridgedCorrelation   QualityFlag = "bridged_correlation"
	FlagNoCorrelationKey     QualityFlag = "no_correlation_key"
	FlagDataDomeFieldsAbsent QualityFlag = "datadome_fields_absent"
)

// KeySource records how a record's correlation key was established, so the UI
// can distinguish an exact join from a heuristic guess (FR-072c).
type KeySource string

const (
	KeySourceRayID           KeySource = "ray_id"
	KeySourceVendorRequestID KeySource = "vendor_request_id"
	KeySourceHeuristic       KeySource = "heuristic"
	KeySourceNone            KeySource = "none"
)

// Event is one provider record expressed in the common schema.
type Event struct {
	SchemaVersion string   `json:"schema_version"`
	EventID       string   `json:"event_id"`
	RawID         string   `json:"raw_id"`
	Tenant        string   `json:"tenant"`
	Provider      Provider `json:"provider"`
	Dataset       string   `json:"dataset,omitempty"`
	ParserVersion string   `json:"parser_version"`

	// Identifiers holds EVERY per-request identifier this record carries.
	// Correlation unions records transitively across shared identifiers, so a
	// record carrying two identifiers bridges two identifier spaces — this is
	// what lets a DataDome record join an nginx record through the Cloudflare
	// record that knows both (research.md R11a, FR-072f).
	Identifiers []string `json:"identifiers,omitempty"`

	CorrelationKey       string    `json:"correlation_key,omitempty"`
	CorrelationKeySource KeySource `json:"correlation_key_source,omitempty"`
	RayID                string    `json:"ray_id,omitempty"`
	VendorRequestID      string    `json:"vendor_request_id,omitempty"`

	// EventTime is when the event happened at the provider; ReceivedAt is when we
	// received it. Both are required and kept distinct (FR-011).
	EventTime   time.Time   `json:"event_time"`
	ReceivedAt  time.Time   `json:"received_at"`
	ClockSkewMS int64       `json:"clock_skew_ms,omitempty"`
	TimeQuality TimeQuality `json:"time_quality,omitempty"`

	Layer          Layer `json:"layer"`
	LayerOrderHint int   `json:"layer_order_hint"`

	Client   Client   `json:"client"`
	Request  Request  `json:"request"`
	Response Response `json:"response"`
	Verdict  Verdict  `json:"verdict"`
	Bot      *Bot     `json:"bot,omitempty"`
	// Shape holds pre-masking structural measurements (schema 1.1); nil when
	// the provider ships none of them.
	Shape *Shape `json:"shape,omitempty"`

	DataQualityFlags []QualityFlag  `json:"data_quality_flags,omitempty"`
	UnmappedFields   map[string]any `json:"unmapped_fields,omitempty"`
	MaskedFields     []string       `json:"masked_fields,omitempty"`
}

type Client struct {
	IP        string `json:"ip,omitempty"`
	ASN       int    `json:"asn,omitempty"`
	Country   string `json:"country,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
}

type Request struct {
	Method        string            `json:"method,omitempty"`
	Host          string            `json:"host,omitempty"`
	Path          string            `json:"path,omitempty"`
	Query         string            `json:"query,omitempty"`
	HTTPVersion   string            `json:"http_version,omitempty"`
	Headers       map[string]string `json:"headers,omitempty"`
	BodyRef       string            `json:"body_ref,omitempty"`
	BodyTruncated bool              `json:"body_truncated,omitempty"`
}

// Shape carries structural facts about a request, derived at NORMALIZATION —
// before the masker runs — and safe to keep afterwards: counting a cookie is
// not storing a cookie. These are integers and names, never values.
//
// Every field is a pointer because an absent measurement and a measured zero
// are different claims (the FR-070 principle): nil means the provider never
// shipped the fact. Each parser sets only what its provider genuinely
// measures — a value that would be a lying floor (e.g. request bytes from a
// truncated ASM capture) stays nil rather than understating a ceiling.
type Shape struct {
	// RequestBytes is the total size of the request including headers, as the
	// provider measured it (Cloudflare ClientRequestBytes, nginx $request_length).
	RequestBytes *int64 `json:"request_bytes,omitempty"`
	// HeaderCount and HeaderBytes describe the FULL header block, so they are
	// set only when the provider ships every header (F5 ASM's captured
	// request), never from a configured subset like Logpush RequestHeaders.
	HeaderCount *int `json:"header_count,omitempty"`
	HeaderBytes *int `json:"header_bytes,omitempty"`
	// CookieCount and CookieNames come from the Cookie request header. Names
	// only — the value is split away before it can be recorded.
	CookieCount *int     `json:"cookie_count,omitempty"`
	CookieNames []string `json:"cookie_names,omitempty"`
	// BodyForm is the request body's parameters as a form-encoded string
	// (name=value&...), from providers that ship the body (F5 ASM). Values that
	// look like secrets are blanked at capture, so a password field survives as
	// a name with no value. Present only for form/JSON bodies the capture could
	// parse; a truncated body yields whatever parsed.
	BodyForm string `json:"body_form,omitempty"`
}

type Response struct {
	Status     int     `json:"status,omitempty"`
	Bytes      int64   `json:"bytes,omitempty"`
	DurationMS float64 `json:"duration_ms,omitempty"`
	// CacheStatus is Cloudflare's CacheCacheStatus. A cache hit means the edge
	// served the response without contacting the origin — so the origin's
	// absence from the flow is expected, not a gap.
	CacheStatus string `json:"cache_status,omitempty"`
}

// Verdict is one layer's decision, with the provider's own reason preserved
// verbatim alongside the normalized interpretation (FR-026, FR-028).
type Verdict struct {
	Action      Action         `json:"action"`
	Terminating bool           `json:"terminating"`
	RuleID      string         `json:"rule_id,omitempty"`
	RuleName    string         `json:"rule_name,omitempty"`
	RuleVersion string         `json:"rule_version,omitempty"`
	Category    string         `json:"category,omitempty"`
	Score       *float64       `json:"score,omitempty"`
	Threshold   *float64       `json:"threshold,omitempty"`
	ReasonRaw   map[string]any `json:"reason_raw,omitempty"`
	// Mapped is false when the provider reported a value we do not recognize.
	// The value is still surfaced verbatim in ReasonRaw (FR-014).
	Mapped bool `json:"mapped"`
}

// Bot carries bot-management signals. DataDome's bot score is deliberately kept
// distinct from a WAF threat score: a high bot score on an allowed request is a
// score conflict worth surfacing, whereas a WAF threat rating on an allowed
// request is only a severity hint.
type Bot struct {
	CFBotScore        *int     `json:"cf_bot_score,omitempty"`
	DataDomePresent   bool     `json:"datadome_present"`
	DataDomeIsBot     string   `json:"datadome_isbot,omitempty"`
	DataDomeBotName   string   `json:"datadome_botname,omitempty"`
	DataDomeRuleType  string   `json:"datadome_ruletype,omitempty"`
	DataDomeScore     *float64 `json:"datadome_score,omitempty"`
	DataDomeRiskScore *float64 `json:"datadome_riskscore,omitempty"`
	DataDomeAction    string   `json:"datadome_action,omitempty"`
}

// HasFlag reports whether the event carries a given quality flag.
func (e *Event) HasFlag(f QualityFlag) bool {
	for _, got := range e.DataQualityFlags {
		if got == f {
			return true
		}
	}
	return false
}

// AddFlag records a quality condition once. Flags are a set, not a log: repeating
// the same condition should not inflate the list.
func (e *Event) AddFlag(f QualityFlag) {
	if !e.HasFlag(f) {
		e.DataQualityFlags = append(e.DataQualityFlags, f)
	}
}
