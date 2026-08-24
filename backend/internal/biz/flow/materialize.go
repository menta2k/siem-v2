package flow

import (
	"sort"
	"strings"
	"time"

	"github.com/menta2k/siem-v2/backend/internal/correlate"
	"github.com/menta2k/siem-v2/backend/internal/correlate/keys"
	"github.com/menta2k/siem-v2/backend/internal/normalize/schema"
)

// expectedLayers is the request path this deployment monitors. A layer absent
// from a flow is reported as missing rather than omitted, because "we never
// heard from the WAF" and "the WAF allowed it" are completely different facts
// and must never look the same (FR-019).
var expectedLayers = []schema.Layer{
	schema.LayerEdge,
	schema.LayerBotManagement,
	schema.LayerAppFirewall,
	schema.LayerOrigin,
}

// Options controls materialization.
type Options struct {
	Tenant string
	// ExpectedLayers overrides the default four-layer request path. A deployment
	// that genuinely monitors fewer layers (no WAF, say) must not have every
	// complete flow read as partial — but the default stays the full path, so
	// forgetting to set this errs toward reporting gaps rather than hiding them.
	ExpectedLayers []schema.Layer
	// Method and Bridged come from the correlation stage.
	Method  keys.Tier
	Bridged bool
	// Closed marks a flow whose late-arrival window has elapsed. An open flow is
	// never reported as Partial: it may simply not have finished arriving.
	Closed bool
	Now    time.Time
}

// Materialize turns a correlated set of events into a Flow.
//
// It is a pure function of its inputs. That is what makes FR-022 hold —
// reprocessing the same records yields an identical flow — and it is why the
// caller supplies Now rather than this reading the clock.
func Materialize(correlationKey string, events []schema.Event, opts Options) *Flow {
	if len(events) == 0 {
		return nil
	}
	ordered := correlate.OrderEvents(events)

	f := &Flow{
		FlowID:         flowID(correlationKey),
		Tenant:         opts.Tenant,
		CorrelationKey: correlationKey,
		Events:         ordered,
		Method:         opts.Method,
		Bridged:        opts.Bridged,
	}

	f.FirstSeen, f.LastSeen = timeSpan(ordered)
	var verdictConflict bool
	f.EffectiveOutcome, f.TerminatingLayer, verdictConflict = resolveOutcome(ordered)

	// Coverage is judged only up to the TERMINATING layer: a request blocked at
	// the edge legitimately never reached the origin, so the origin's absence
	// is not a gap. Missing a layer ABOVE the termination point is a real gap —
	// a layer that should have reported did not (the design's meaning of
	// "partial"). A flow that passed all the way through expects every layer.
	expected := opts.ExpectedLayers
	if len(expected) == 0 {
		expected = expectedLayers
	}
	// Completeness is judged only up to the boundary layer — the point past
	// which the request legitimately never went, so a deeper layer's absence
	// is not a gap.
	expected = expectedUpTo(expected, completenessBoundary(ordered, f.TerminatingLayer))
	f.LayersPresent, f.LayersMissing = layerCoverage(ordered, expected)
	f.TimingAttribution = timingAttribution(ordered)
	f.Client, f.Request = denormalize(ordered)
	f.Completeness = completeness(f, opts.Closed)
	f.Confidence = confidence(f)

	if opts.Closed {
		closed := opts.Now
		f.ClosedAt = &closed
	}

	propagateFlags(f, ordered)
	flagVerdictConflict(f, verdictConflict)
	return f
}

// layerCoverage reports which expected layers reported and which did not.
// completenessBoundary is the deepest layer the request is known to have
// reached, so coverage below it is genuinely absent rather than lost:
//
//   - the DEEPEST layer that actually has a record — if the origin logged the
//     request, it passed every layer above it, even a response-side WAF block
//     (F5's "Illegal redirection attempt" blocks the origin's response, so the
//     origin record is real and expected);
//   - the terminating layer, when a request-path block stopped it early;
//   - the origin, for an allowed request that was NOT a cache hit (it should
//     have reached the origin; a missing origin record is then a real gap).
//
// The deepest of these wins.
func completenessBoundary(ordered []schema.Event, terminating schema.Layer) schema.Layer {
	best := schema.LayerEdge
	bestOrder := 0
	consider := func(l schema.Layer) {
		if o, ok := l.Order(); ok && o > bestOrder {
			best, bestOrder = l, o
		}
	}
	for _, e := range ordered {
		consider(e.Layer)
	}
	if terminating != "" {
		consider(terminating)
	}
	// Allowed and not cache-served: the request should have reached the origin.
	if terminating == "" && !edgeServedFromCache(ordered) {
		consider(schema.LayerOrigin)
	}
	return best
}

// cacheServedStatuses are the Cloudflare CacheCacheStatus values that mean the
// edge answered from cache without going to the origin.
var cacheServedStatuses = map[string]bool{
	"hit": true, "revalidated": true, "updating": true, "stale": true,
}

// edgeServedFromCache reports whether the edge event shows a cache hit.
func edgeServedFromCache(events []schema.Event) bool {
	for _, e := range events {
		if e.Layer == schema.LayerEdge && cacheServedStatuses[strings.ToLower(e.Response.CacheStatus)] {
			return true
		}
	}
	return false
}

// expectedUpTo trims the expected layer set to those at or above the
// terminating layer in causal order. An empty terminating layer (the request
// passed through without any layer terminating it) expects the full set.
func expectedUpTo(expected []schema.Layer, terminating schema.Layer) []schema.Layer {
	if terminating == "" {
		return expected
	}
	limit, ok := terminating.Order()
	if !ok {
		return expected
	}
	out := make([]schema.Layer, 0, len(expected))
	for _, l := range expected {
		if o, ok := l.Order(); ok && o <= limit {
			out = append(out, l)
		}
	}
	return out
}

func layerCoverage(events []schema.Event, expected []schema.Layer) (present, missing []schema.Layer) {
	seen := map[schema.Layer]bool{}
	for _, e := range events {
		seen[e.Layer] = true
	}
	for _, l := range expected {
		if seen[l] {
			present = append(present, l)
		} else {
			missing = append(missing, l)
		}
	}
	return present, missing
}

// resolveOutcome determines what actually happened to the request, returning
// the effective action, the terminating layer, and whether a terminating
// verdict was contradicted by a downstream delivery.
//
// The terminating layer is the FIRST layer in causal order that took a
// terminating action: once the edge blocks a request, a later layer's opinion is
// advisory at best and usually did not see the request at all. Reporting the last
// verdict instead would credit the wrong system with the block (FR-027).
//
// A block is only effective if the request did not go on to be SERVED by a
// deeper layer. In a bridged multi-ray flow a terminating verdict from one
// Cloudflare ray can be merged with another ray's successful origin delivery
// (e.g. DataDome returns hard_block on the parent ray while the bridged ray is
// served 200 from origin); crediting the block would report a request that was
// actually delivered as blocked. When a delivery is observed strictly deeper
// than a terminating verdict, that verdict did not take effect: skip it and
// signal a conflict so the reconciliation stays auditable.
func resolveOutcome(ordered []schema.Event) (schema.Action, schema.Layer, bool) {
	servedAt, served := servedLayer(ordered)
	servedOrder, _ := servedAt.Order()
	conflict := false
	for _, e := range ordered {
		if !e.Verdict.Terminating {
			continue
		}
		if served {
			if lo, ok := e.Layer.Order(); ok && servedOrder > lo {
				conflict = true
				continue
			}
		}
		return e.Verdict.Action, e.Layer, conflict
	}
	// Nothing (still standing) terminated it. The outcome is what the deepest
	// layer reported, since that is the closest thing to what the client
	// actually received.
	last := ordered[len(ordered)-1]
	return last.Verdict.Action, "", conflict
}

// servedLayer returns the deepest layer that actually delivered a response to
// the client — a non-terminating verdict with a 2xx/3xx status — and whether
// one exists. A delivery downstream of a block is proof the block never took
// effect.
func servedLayer(ordered []schema.Event) (schema.Layer, bool) {
	var deepest schema.Layer
	found := false
	best := -1
	for _, e := range ordered {
		if e.Verdict.Terminating {
			continue
		}
		if s := e.Response.Status; s < 200 || s >= 400 {
			continue
		}
		if o, ok := e.Layer.Order(); ok && o > best {
			best, deepest, found = o, e.Layer, true
		}
	}
	return deepest, found
}

// timingAttribution records each layer's observed duration where the underlying
// records support it (FR-029).
func timingAttribution(ordered []schema.Event) map[schema.Layer]float64 {
	out := map[schema.Layer]float64{}
	for _, e := range ordered {
		if e.Response.DurationMS > 0 {
			out[e.Layer] += e.Response.DurationMS
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// denormalize lifts client and request attributes from the most authoritative
// event. The edge sees the true client address before any proxy hop rewrites it,
// so earlier layers are preferred; later layers fill only what is still missing.
func denormalize(ordered []schema.Event) (schema.Client, schema.Request) {
	var c schema.Client
	var r schema.Request
	for _, e := range ordered {
		if c.IP == "" {
			c.IP = e.Client.IP
		}
		if c.ASN == 0 {
			c.ASN = e.Client.ASN
		}
		if c.Country == "" {
			c.Country = e.Client.Country
		}
		if c.UserAgent == "" {
			c.UserAgent = e.Client.UserAgent
		}
		if r.Method == "" {
			r.Method = e.Request.Method
		}
		if r.Host == "" {
			r.Host = e.Request.Host
		}
		if r.Path == "" {
			r.Path = e.Request.Path
		}
		if r.Query == "" {
			r.Query = e.Request.Query
		}
	}
	return c, r
}

func completeness(f *Flow, closed bool) Completeness {
	if f.Method == keys.TierNone {
		return Ambiguous
	}
	if len(f.LayersMissing) == 0 {
		return Complete
	}
	// An open flow with gaps is not partial — the rest may still be arriving.
	// Calling it partial early would show analysts a false gap.
	if !closed {
		return Complete
	}
	return Partial
}

// confidence scores how much to trust the join. Exact joins are certain by
// construction; heuristic joins are not, and the score degrades with how little
// corroboration the flow has.
func confidence(f *Flow) float64 {
	switch f.Method {
	case keys.TierExact:
		return 1.0
	case keys.TierHeuristic:
		score := 0.6
		if len(f.LayersPresent) >= 3 {
			score += 0.1
		}
		if f.HasFlag(schema.FlagClockSkew) {
			score -= 0.2
		}
		return score
	default:
		return 0.0
	}
}

// propagateFlags lifts event-level quality conditions to the flow, and adds the
// flow-level ones. An analyst reads the flow, not each event, so a condition that
// stays buried on one event is invisible in practice (FR-070).
func propagateFlags(f *Flow, ordered []schema.Event) {
	for _, e := range ordered {
		for _, flag := range e.DataQualityFlags {
			f.addFlag(flag)
		}
	}
	if skewed, _ := correlate.DetectSkew(ordered); skewed {
		f.addFlag(schema.FlagClockSkew)
	}
	if f.Method == keys.TierHeuristic {
		f.addFlag(schema.FlagHeuristicCorrelation)
	}
	if f.Bridged {
		f.addFlag(schema.FlagBridgedCorrelation)
	}
}

// flagVerdictConflict records that a terminating verdict was overruled by a
// downstream delivery during outcome resolution (see resolveOutcome).
func flagVerdictConflict(f *Flow, conflict bool) {
	if conflict {
		f.addFlag(schema.FlagVerdictConflict)
	}
}

func timeSpan(ordered []schema.Event) (first, last time.Time) {
	for i, e := range ordered {
		if e.EventTime.IsZero() {
			continue
		}
		if i == 0 || first.IsZero() || e.EventTime.Before(first) {
			first = e.EventTime
		}
		if e.EventTime.After(last) {
			last = e.EventTime
		}
	}
	return first, last
}

// flowID derives a stable id from the correlation key. Deterministic by design:
// reprocessing must produce the same flow id, not a duplicate flow (FR-022).
func flowID(correlationKey string) string {
	return "flow:" + correlationKey
}

// SortFlows orders flows newest-first for display.
func SortFlows(flows []*Flow) {
	sort.SliceStable(flows, func(i, j int) bool {
		return flows[i].FirstSeen.After(flows[j].FirstSeen)
	})
}
