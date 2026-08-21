package profile

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// Caps bound profile growth. Every cap trips a flag or counter rather than
// silently dropping — a truncated profile must never read as a complete one.
type Caps struct {
	EndpointsPerTenant int
	EndpointsPerHost   int
	ParamsPerEndpoint  int
	EnumValues         int
	StatusValues       int
	CookieNames        int
}

func DefaultCaps() Caps {
	return Caps{
		EndpointsPerTenant: 20000,
		EndpointsPerHost:   5000,
		ParamsPerEndpoint:  200,
		EnumValues:         64,
		StatusValues:       32,
		CookieNames:        64,
	}
}

// ParamLocation says where a parameter was observed.
type ParamLocation string

const (
	LocationQuery ParamLocation = "query"
	LocationPath  ParamLocation = "path"
)

// ParamProfile is the learned baseline of one parameter of one endpoint.
type ParamProfile struct {
	Location ParamLocation `json:"location"`
	Name     string        `json:"name"`
	Type     ValueType     `json:"inferred_type"`
	// Observations counts endpoint requests since this parameter was first
	// seen; PresentCount counts the ones that actually carried it. The ratio is
	// the measured "required vs optional".
	Observations int64 `json:"observations"`
	PresentCount int64 `json:"present_count"`
	MinLen       int   `json:"min_len"`
	MaxLen       int   `json:"max_len"`
	// DistinctEstimate is exact until EnumOverflowed, then a floor.
	DistinctEstimate int64 `json:"distinct_estimate"`
	// EnumValues holds observed values ONLY while cardinality stays under the
	// cap — an enum candidate. Values that look like secrets are never stored.
	EnumValues     map[string]int64 `json:"enum_values,omitempty"`
	EnumOverflowed bool             `json:"enum_overflowed"`
	FirstSeen      time.Time        `json:"first_seen"`
	LastSeen       time.Time        `json:"last_seen"`
}

// EndpointProfile is the learned baseline of one endpoint: a (tenant, host,
// method, path template) unit.
//
// Structural maxima are pointers: nil is "never measured", which is a
// different claim from a measured zero (FR-070's principle). Header, cookie
// and request-byte ceilings stay nil until the capture extension (plan §3.2)
// ships, because no stored event carries them today.
type EndpointProfile struct {
	ID           string `json:"id"`
	Tenant       string `json:"tenant"`
	Host         string `json:"host"`
	Method       string `json:"method"`
	PathTemplate string `json:"path_template"`

	Observations int64     `json:"observations"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`

	MaxRequestBytes *int64 `json:"max_request_bytes,omitempty"`
	MaxHeaderCount  *int   `json:"max_header_count,omitempty"`
	MaxHeaderBytes  *int   `json:"max_header_bytes,omitempty"`
	MaxCookieCount  *int   `json:"max_cookie_count,omitempty"`
	MaxParamCount   *int   `json:"max_param_count,omitempty"`
	MaxValueLen     *int   `json:"max_value_len,omitempty"`
	MaxPathLen      *int   `json:"max_path_len,omitempty"`

	CookieNames map[string]bool  `json:"cookie_names,omitempty"`
	StatusMix   map[string]int64 `json:"status_mix,omitempty"`
	Providers   map[string]bool  `json:"providers,omitempty"`

	// Truncated is set when a cap stopped this profile from growing (parameter
	// cap, enum caps). The profile keeps updating what it already tracks.
	Truncated bool `json:"truncated"`

	Params map[string]*ParamProfile `json:"params,omitempty"`
}

// EndpointID is deterministic so replaying the same flows yields the same
// rows (Constitution VI) and an upsert can never duplicate an endpoint.
func EndpointID(tenant, host, method, pathTemplate string) string {
	h := sha256.Sum256([]byte(tenant + "\x00" + host + "\x00" + method + "\x00" + pathTemplate))
	return "ep_" + hex.EncodeToString(h[:12])
}

// paramKey doubles as the JSON object key for a parameter in the params jsonb
// column, so its separator must be a byte PostgreSQL jsonb accepts. NUL (0x00)
// serialises to a \u0000 escape that jsonb rejects (SQLSTATE 22P05), silently
// failing every flush; the Unit Separator (0x1F) is kept by jsonb and never
// appears in a real parameter name.
func paramKey(loc ParamLocation, name string) string { return string(loc) + "\x1f" + name }

// maxInt lifts a measured value into a nil-able ceiling.
func maxInt(cur *int, v int) *int {
	if cur == nil || v > *cur {
		return &v
	}
	return cur
}

// merge folds another endpoint's evidence into this one. Used when a new path
// collapse unifies previously-literal siblings: /job/8584286 and /job/8584287
// become one /job/{int}. Every field is a monotonic merge, so merging is
// commutative and idempotent-ish under replay.
func (p *EndpointProfile) merge(o *EndpointProfile, caps Caps) {
	p.Observations += o.Observations
	if o.FirstSeen.Before(p.FirstSeen) {
		p.FirstSeen = o.FirstSeen
	}
	if o.LastSeen.After(p.LastSeen) {
		p.LastSeen = o.LastSeen
	}
	if o.MaxRequestBytes != nil && (p.MaxRequestBytes == nil || *o.MaxRequestBytes > *p.MaxRequestBytes) {
		p.MaxRequestBytes = o.MaxRequestBytes
	}
	for _, pair := range []struct {
		dst **int
		src *int
	}{
		{&p.MaxHeaderCount, o.MaxHeaderCount},
		{&p.MaxHeaderBytes, o.MaxHeaderBytes},
		{&p.MaxCookieCount, o.MaxCookieCount},
		{&p.MaxParamCount, o.MaxParamCount},
		{&p.MaxValueLen, o.MaxValueLen},
		{&p.MaxPathLen, o.MaxPathLen},
	} {
		if pair.src != nil {
			*pair.dst = maxInt(*pair.dst, *pair.src)
		}
	}
	for name := range o.CookieNames {
		if len(p.CookieNames) >= caps.CookieNames {
			p.Truncated = true
			break
		}
		if p.CookieNames == nil {
			p.CookieNames = map[string]bool{}
		}
		p.CookieNames[name] = true
	}
	for status, n := range o.StatusMix {
		if _, seen := p.StatusMix[status]; !seen && len(p.StatusMix) >= caps.StatusValues {
			p.Truncated = true
			continue
		}
		if p.StatusMix == nil {
			p.StatusMix = map[string]int64{}
		}
		p.StatusMix[status] += n
	}
	for prov := range o.Providers {
		if p.Providers == nil {
			p.Providers = map[string]bool{}
		}
		p.Providers[prov] = true
	}
	p.Truncated = p.Truncated || o.Truncated

	for key, op := range o.Params {
		pp := p.Params[key]
		if pp == nil {
			if len(p.Params) >= caps.ParamsPerEndpoint {
				p.Truncated = true
				continue
			}
			if p.Params == nil {
				p.Params = map[string]*ParamProfile{}
			}
			p.Params[key] = op
			continue
		}
		pp.merge(op, caps)
	}
}

func (pp *ParamProfile) merge(o *ParamProfile, caps Caps) {
	pp.Type = Join(pp.Type, o.Type)
	pp.Observations += o.Observations
	pp.PresentCount += o.PresentCount
	if o.MinLen < pp.MinLen {
		pp.MinLen = o.MinLen
	}
	if o.MaxLen > pp.MaxLen {
		pp.MaxLen = o.MaxLen
	}
	if o.FirstSeen.Before(pp.FirstSeen) {
		pp.FirstSeen = o.FirstSeen
	}
	if o.LastSeen.After(pp.LastSeen) {
		pp.LastSeen = o.LastSeen
	}
	if pp.EnumOverflowed || o.EnumOverflowed {
		pp.overflowEnum()
		if o.DistinctEstimate > pp.DistinctEstimate {
			pp.DistinctEstimate = o.DistinctEstimate
		}
		return
	}
	for v, n := range o.EnumValues {
		if _, seen := pp.EnumValues[v]; !seen && len(pp.EnumValues) >= caps.EnumValues {
			pp.overflowEnum()
			return
		}
		if pp.EnumValues == nil {
			pp.EnumValues = map[string]int64{}
		}
		pp.EnumValues[v] += n
	}
	pp.DistinctEstimate = int64(len(pp.EnumValues))
}

// overflowEnum abandons the enum candidate: past the cap the values are noise
// to keep and a liability to store.
func (pp *ParamProfile) overflowEnum() {
	if !pp.EnumOverflowed {
		if int64(len(pp.EnumValues)) > pp.DistinctEstimate {
			pp.DistinctEstimate = int64(len(pp.EnumValues))
		}
		pp.EnumValues = nil
		pp.EnumOverflowed = true
	}
}
