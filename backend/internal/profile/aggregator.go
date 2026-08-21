package profile

import (
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/menta2k/siem-v2/backend/internal/normalize"
)

// Observation is what the profiler learns from: one completed flow, reduced to
// the request facts a baseline is built on.
type Observation struct {
	FlowID string
	Tenant string
	Host   string
	Method string
	Path   string
	Query  string
	// Body is the request body's parameters as a form-encoded string
	// (name=value&...), secret-filtered at capture. Empty unless the tenant
	// opted into body profiling and a provider shipped a parseable body.
	Body      string
	Status    int
	Providers []string
	Seen      time.Time

	// Shape facts (schema 1.1), merged across the flow's events by the caller.
	// nil = no event measured it; the ceiling stays honestly absent.
	RequestBytes *int64
	HeaderCount  *int
	HeaderBytes  *int
	CookieCount  *int
	// CookieNames arrive only when the tenant opted into recording names;
	// the caller strips them to a count otherwise.
	CookieNames []string
}

// Stats are the aggregator's own health signals (Constitution IV): zero
// endpoints learned while observations flow is the failure mode that must be
// as loud as an attack.
type Stats struct {
	Observed      int64 `json:"observed"`
	Deduplicated  int64 `json:"deduplicated"`
	CapHits       int64 `json:"cap_hits"`
	Endpoints     int   `json:"endpoints"`
	DirtyPending  int   `json:"dirty_pending"`
	Collapses     int64 `json:"collapses"`
	SecretsSeen   int64 `json:"secrets_withheld"`
	InvalidQuery  int64 `json:"invalid_query_strings"`
	RetiredMerged int64 `json:"retired_merged"`
}

type scopeKey struct{ tenant, host, method string }

// Aggregator folds observations into endpoint profiles.
//
// It is written for a single observing goroutine (profilerd's consume loop);
// the mutex exists so Stats can be read from the health endpoint without
// racing it, not to support concurrent observers.
type Aggregator struct {
	mu    sync.Mutex
	caps  Caps
	topts TemplateOptions
	now   func() time.Time

	engines   map[scopeKey]*Engine
	endpoints map[string]*EndpointProfile
	byScope   map[scopeKey]map[string]bool

	tenantCount map[string]int
	hostCount   map[string]int // tenant + "\x00" + host

	dirty   map[string]bool
	retired map[string]bool

	// seen deduplicates flow IDs: a flow amended after close is re-stored and
	// re-published under the same ID, and counters are the one thing that is
	// not idempotent under that replay.
	seen      map[string]time.Time
	seenTTL   time.Duration
	lastPrune time.Time

	stats Stats
}

func NewAggregator(caps Caps, topts TemplateOptions) *Aggregator {
	if caps.EndpointsPerTenant == 0 {
		caps = DefaultCaps()
	}
	if topts.MinSamples == 0 {
		topts = DefaultTemplateOptions()
	}
	return &Aggregator{
		caps:        caps,
		topts:       topts,
		now:         func() time.Time { return time.Now().UTC() },
		engines:     map[scopeKey]*Engine{},
		endpoints:   map[string]*EndpointProfile{},
		byScope:     map[scopeKey]map[string]bool{},
		tenantCount: map[string]int{},
		hostCount:   map[string]int{},
		dirty:       map[string]bool{},
		retired:     map[string]bool{},
		seen:        map[string]time.Time{},
		seenTTL:     2 * time.Hour,
	}
}

// Load seeds the aggregator from stored profiles at startup. Learned templates
// are replayed into the engines so collapse decisions survive restart —
// monotonicity depends on it.
func (a *Aggregator) Load(profiles []*EndpointProfile) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, p := range profiles {
		sk := scopeKey{p.Tenant, p.Host, p.Method}
		a.endpoints[p.ID] = p
		if a.byScope[sk] == nil {
			a.byScope[sk] = map[string]bool{}
		}
		a.byScope[sk][p.ID] = true
		a.tenantCount[p.Tenant]++
		a.hostCount[p.Tenant+"\x00"+p.Host]++
		a.engine(sk).LearnTemplate(p.PathTemplate)
	}
}

func (a *Aggregator) engine(sk scopeKey) *Engine {
	e := a.engines[sk]
	if e == nil {
		e = NewEngine(a.topts)
		a.engines[sk] = e
	}
	return e
}

// Observe folds one flow into the profiles.
func (a *Aggregator) Observe(o Observation) {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := o.Seen
	if now.IsZero() {
		now = a.now()
	}

	if o.FlowID != "" {
		if _, dup := a.seen[o.FlowID]; dup {
			a.stats.Deduplicated++
			return
		}
		a.seen[o.FlowID] = now
		a.pruneSeen(now)
	}
	a.stats.Observed++

	// PostgreSQL rejects NUL bytes in text columns and, as the \u0000 escape, in
	// jsonb (SQLSTATE 22P05). Scanner traffic carries them routinely, so strip
	// them at the capture boundary before any string reaches host/path text,
	// cookie_names, or the params jsonb.
	o.Host = stripNUL(o.Host)
	o.Method = stripNUL(o.Method)
	o.Path = stripNUL(o.Path)

	host := canonicalHost(o.Host)
	method := strings.ToUpper(strings.TrimSpace(o.Method))
	if method == "" {
		method = "UNKNOWN"
	}
	sk := scopeKey{o.Tenant, host, method}

	eng := a.engine(sk)
	norm, collapsed := eng.Normalize(o.Path)
	if collapsed {
		a.stats.Collapses++
		a.renormalizeScope(sk, eng)
	}
	template := JoinTemplate(norm)
	id := EndpointID(o.Tenant, host, method, template)

	ep := a.endpoints[id]
	if ep == nil {
		if a.tenantCount[o.Tenant] >= a.caps.EndpointsPerTenant ||
			a.hostCount[o.Tenant+"\x00"+host] >= a.caps.EndpointsPerHost {
			a.stats.CapHits++
			return
		}
		ep = &EndpointProfile{
			ID: id, Tenant: o.Tenant, Host: host, Method: method,
			PathTemplate: template, FirstSeen: now, LastSeen: now,
		}
		a.endpoints[id] = ep
		if a.byScope[sk] == nil {
			a.byScope[sk] = map[string]bool{}
		}
		a.byScope[sk][id] = true
		a.tenantCount[o.Tenant]++
		a.hostCount[o.Tenant+"\x00"+host]++
	}

	a.observeEndpoint(ep, o, norm, now)
	a.dirty[id] = true
	a.stats.DirtyPending = len(a.dirty)
	a.stats.Endpoints = len(a.endpoints)
}

func (a *Aggregator) observeEndpoint(ep *EndpointProfile, o Observation, norm []string, now time.Time) {
	ep.Observations++
	if now.Before(ep.FirstSeen) {
		ep.FirstSeen = now
	}
	if now.After(ep.LastSeen) {
		ep.LastSeen = now
	}
	ep.MaxPathLen = maxInt(ep.MaxPathLen, len(o.Path))

	// Measured shape ceilings. Each stays nil until some provider ships the
	// fact — a measured zero and an absent measurement are different claims.
	if o.RequestBytes != nil && (ep.MaxRequestBytes == nil || *o.RequestBytes > *ep.MaxRequestBytes) {
		v := *o.RequestBytes
		ep.MaxRequestBytes = &v
	}
	if o.HeaderCount != nil {
		ep.MaxHeaderCount = maxInt(ep.MaxHeaderCount, *o.HeaderCount)
	}
	if o.HeaderBytes != nil {
		ep.MaxHeaderBytes = maxInt(ep.MaxHeaderBytes, *o.HeaderBytes)
	}
	if o.CookieCount != nil {
		ep.MaxCookieCount = maxInt(ep.MaxCookieCount, *o.CookieCount)
	}
	for _, name := range o.CookieNames {
		name = stripNUL(name)
		if ep.CookieNames[name] {
			continue
		}
		if len(ep.CookieNames) >= a.caps.CookieNames {
			ep.Truncated = true
			break
		}
		if ep.CookieNames == nil {
			ep.CookieNames = map[string]bool{}
		}
		ep.CookieNames[name] = true
	}

	if o.Status > 0 {
		key := strconv.Itoa(o.Status)
		if _, seen := ep.StatusMix[key]; seen || len(ep.StatusMix) < a.caps.StatusValues {
			if ep.StatusMix == nil {
				ep.StatusMix = map[string]int64{}
			}
			ep.StatusMix[key]++
		} else {
			ep.Truncated = true
		}
	}
	for _, prov := range o.Providers {
		if prov == "" {
			continue
		}
		if ep.Providers == nil {
			ep.Providers = map[string]bool{}
		}
		ep.Providers[prov] = true
	}

	present := map[string]bool{}

	// Path parameters: positions the template turned into tokens. Named by
	// position — a path parameter has no name of its own.
	raw := SplitPath(o.Path)
	for i, seg := range norm {
		if _, isTok := ParseToken(seg); !isTok || i >= len(raw) {
			continue
		}
		key := a.observeParam(ep, LocationPath, "position "+strconv.Itoa(i+1), raw[i], now)
		if key != "" {
			present[key] = true
		}
	}

	// Query and body parameters, parsed identically (both form-encoded). Body
	// values were secret-filtered at capture; observeParam filters again as
	// defence in depth. MaxParamCount is the query+body total of one request.
	observeParams := func(loc ParamLocation, raw string) int {
		if raw == "" {
			return 0
		}
		values, err := url.ParseQuery(raw)
		if err != nil {
			a.stats.InvalidQuery++
		}
		names := make([]string, 0, len(values))
		for name := range values {
			names = append(names, name)
		}
		sort.Strings(names) // deterministic cap behaviour under replay
		for _, name := range names {
			for _, v := range values[name] {
				ep.MaxValueLen = maxInt(ep.MaxValueLen, len(v))
				if key := a.observeParam(ep, loc, name, v, now); key != "" {
					present[key] = true
				}
			}
		}
		return len(names)
	}
	paramCount := observeParams(LocationQuery, o.Query)
	paramCount += observeParams(LocationBody, o.Body)
	ep.MaxParamCount = maxInt(ep.MaxParamCount, paramCount)

	// Absence is evidence too: a parameter's presence rate needs a denominator
	// counting the requests that did NOT carry it.
	for key, pp := range ep.Params {
		if !present[key] {
			pp.Observations++
		}
	}
}

// observeParam records one value of one parameter, returning the param key or
// "" when the parameter cap refused a new entry.
func (a *Aggregator) observeParam(ep *EndpointProfile, loc ParamLocation, name, value string, now time.Time) string {
	name = NormalizeParamName(stripNUL(name))
	value = stripNUL(value)
	key := paramKey(loc, name)
	pp := ep.Params[key]
	if pp == nil {
		if len(ep.Params) >= a.caps.ParamsPerEndpoint {
			ep.Truncated = true
			return ""
		}
		if ep.Params == nil {
			ep.Params = map[string]*ParamProfile{}
		}
		pp = &ParamProfile{
			Location: loc, Name: name, Type: TypeEmpty,
			MinLen: len(value), MaxLen: len(value),
			FirstSeen: now, LastSeen: now,
		}
		ep.Params[key] = pp
	}

	pp.Observations++
	pp.PresentCount++
	pp.Type = Join(pp.Type, Infer(value))
	if len(value) < pp.MinLen {
		pp.MinLen = len(value)
	}
	if len(value) > pp.MaxLen {
		pp.MaxLen = len(value)
	}
	if now.After(pp.LastSeen) {
		pp.LastSeen = now
	}
	if now.Before(pp.FirstSeen) {
		pp.FirstSeen = now
	}

	if !pp.EnumOverflowed {
		// A value that looks like a secret is never stored, whatever the
		// cardinality: the profiler must not become the place where a token
		// that slipped into a query string is preserved.
		if normalize.ContainsSecret(value) {
			a.stats.SecretsSeen++
		} else if _, seen := pp.EnumValues[value]; seen || len(pp.EnumValues) < a.caps.EnumValues {
			if pp.EnumValues == nil {
				pp.EnumValues = map[string]int64{}
			}
			pp.EnumValues[value]++
			pp.DistinctEstimate = int64(len(pp.EnumValues))
		} else {
			pp.overflowEnum()
		}
	}
	return key
}

// renormalizeScope replays every endpoint of a scope through the engine after
// a new collapse, merging the previously-literal siblings into the template.
func (a *Aggregator) renormalizeScope(sk scopeKey, eng *Engine) {
	ids := make([]string, 0, len(a.byScope[sk]))
	for id := range a.byScope[sk] {
		ids = append(ids, id)
	}
	sort.Strings(ids) // merge order must not depend on map iteration

	for _, id := range ids {
		ep := a.endpoints[id]
		if ep == nil {
			continue
		}
		newTemplate := eng.Renormalize(ep.PathTemplate)
		if newTemplate == ep.PathTemplate {
			continue
		}
		newID := EndpointID(ep.Tenant, ep.Host, ep.Method, newTemplate)

		delete(a.endpoints, id)
		delete(a.byScope[sk], id)
		delete(a.dirty, id)
		a.retired[id] = true
		a.stats.RetiredMerged++

		target := a.endpoints[newID]
		if target == nil {
			ep.ID = newID
			ep.PathTemplate = newTemplate
			a.endpoints[newID] = ep
			a.byScope[sk][newID] = true
		} else {
			target.merge(ep, a.caps)
			a.tenantCount[ep.Tenant]--
			a.hostCount[ep.Tenant+"\x00"+ep.Host]--
		}
		a.dirty[newID] = true
	}
}

// Collect hands the flush loop everything dirty since the last collect, and
// the IDs retired by template merges. The sets are cleared; a failed flush
// must Requeue what it could not store.
func (a *Aggregator) Collect() (dirty []*EndpointProfile, retired []string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	dirty = make([]*EndpointProfile, 0, len(a.dirty))
	for id := range a.dirty {
		if ep := a.endpoints[id]; ep != nil {
			dirty = append(dirty, ep)
		}
	}
	sort.Slice(dirty, func(i, j int) bool { return dirty[i].ID < dirty[j].ID })
	retired = make([]string, 0, len(a.retired))
	for id := range a.retired {
		retired = append(retired, id)
	}
	sort.Strings(retired)
	a.dirty = map[string]bool{}
	a.retired = map[string]bool{}
	a.stats.DirtyPending = 0
	return dirty, retired
}

// Requeue restores a failed flush's work so the next tick retries it.
func (a *Aggregator) Requeue(dirty []*EndpointProfile, retired []string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, ep := range dirty {
		// The endpoint may have been retired by a merge between Collect and
		// Requeue; only re-mark what still exists.
		if _, ok := a.endpoints[ep.ID]; ok {
			a.dirty[ep.ID] = true
		}
	}
	for _, id := range retired {
		a.retired[id] = true
	}
	a.stats.DirtyPending = len(a.dirty)
}

// Stats returns a copy of the counters for the health endpoint.
func (a *Aggregator) Stats() Stats {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := a.stats
	s.Endpoints = len(a.endpoints)
	s.DirtyPending = len(a.dirty)
	return s
}

func (a *Aggregator) pruneSeen(now time.Time) {
	if now.Sub(a.lastPrune) < a.seenTTL/4 {
		return
	}
	a.lastPrune = now
	for id, at := range a.seen {
		if now.Sub(at) > a.seenTTL {
			delete(a.seen, id)
		}
	}
}

func canonicalHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if i := strings.LastIndex(host, ":"); i > 0 && !strings.Contains(host, "]") {
		host = host[:i]
	}
	return host
}

// stripNUL removes NUL bytes. PostgreSQL cannot store them in text columns and
// rejects them as the \u0000 escape in jsonb (SQLSTATE 22P05); request data
// from scanners carries them routinely. Cheap no-op when absent.
func stripNUL(s string) string {
	if strings.IndexByte(s, 0) < 0 {
		return s
	}
	return strings.ReplaceAll(s, "\x00", "")
}
