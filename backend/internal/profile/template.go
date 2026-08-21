package profile

import (
	"regexp"
	"sort"
	"strings"
)

// TemplateOptions bound when a path position collapses into a parameter.
type TemplateOptions struct {
	// MinSamples is how many observations a position needs before any collapse
	// decision. Below it the evidence is noise.
	MinSamples int
	// MaxDistinct is the distinct-value count above which a position collapses
	// to {var} regardless of type. This is the cost control: without it every
	// /job/<id> is its own endpoint and the table grows with traffic.
	MaxDistinct int
	// MinDistinctForType is the distinct-value floor for a TYPED collapse.
	// Without it, /2024/report (one distinct all-int value) would become
	// /{int}/report on repetition alone.
	MinDistinctForType int
	// TypeShare is the fraction of observations that must share one promotable
	// type for a typed collapse (0.9: a stray literal does not block learning).
	TypeShare float64
	// VarSingletonShare gates the untyped {var} collapse: a high-cardinality,
	// untyped position folds to {var} only when at least this fraction of its
	// tracked values are still seen just once — the signature of an id/slug/token
	// stream. A large but REPEATING vocabulary (a site's real top-level routes)
	// stays literal however big it grows, keeping /front_job_search and /company
	// distinct instead of both becoming /{var}. 0 disables the gate.
	VarSingletonShare float64
	// VarRepeatFactor is how much evidence the untyped collapse needs before it
	// trusts that signal: the position must have >= MaxDistinct*VarRepeatFactor
	// observations. At the instant cardinality first exceeds MaxDistinct every
	// value has been seen about once, so a route vocabulary is momentarily
	// indistinguishable from an id stream; deciding then would wrongly (and
	// monotonically) collapse routes. Waiting lets a real vocabulary repeat.
	VarRepeatFactor int
}

func DefaultTemplateOptions() TemplateOptions {
	return TemplateOptions{
		MinSamples:         64,
		MaxDistinct:        64,
		MinDistinctForType: 8,
		TypeShare:          0.9,
		VarSingletonShare:  0.85,
		VarRepeatFactor:    4,
	}
}

// segStat accumulates the values seen at one position under one normalized
// prefix, until the position either collapses or proves literal.
type segStat struct {
	count      int
	values     map[string]int
	typeCounts map[ValueType]int
	overflow   bool // values map hit its cap; distinct count is a floor
}

// Engine learns path templates for one (tenant, host, method) scope.
//
// Positions collapse monotonically: once /job/{int} exists it never reverts to
// literals, which is what keeps replay deterministic (Constitution VI) and the
// endpoint table bounded (Constitution VII). Literal routes alongside a
// parameter survive: /job/search stays distinct from /job/{int} because
// "search" does not match {int}.
type Engine struct {
	opts TemplateOptions
	// collapses maps a normalized prefix (segments joined by "/", parameters
	// already tokenized) to the parameter type at the NEXT position.
	collapses map[string]ValueType
	// stats holds per-position value statistics for positions that have not
	// collapsed, keyed like collapses.
	stats map[string]*segStat
}

func NewEngine(opts TemplateOptions) *Engine {
	if opts.MinSamples <= 0 {
		opts = DefaultTemplateOptions()
	}
	return &Engine{
		opts:      opts,
		collapses: map[string]ValueType{},
		stats:     map[string]*segStat{},
	}
}

// SplitPath splits a URL path into segments, ignoring empty ones so that
// /a//b, /a/b and /a/b/ describe the same route.
func SplitPath(path string) []string {
	parts := strings.Split(path, "/")
	segs := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			segs = append(segs, p)
		}
	}
	return segs
}

// JoinTemplate renders normalized segments back into a template path.
func JoinTemplate(segs []string) string {
	if len(segs) == 0 {
		return "/"
	}
	return "/" + strings.Join(segs, "/")
}

// paramIndexRE matches a single bracketed array/map index, e.g. the "[335045]"
// in "consent[335045]".
var paramIndexRE = regexp.MustCompile(`\[[^\[\]]*\]`)

// NormalizeParamName folds an array/map index that is a VARIABLE identifier into
// empty brackets, so consent[335045] and consent[336191] collapse to a single
// parameter consent[] instead of hundreds of one-off keys that blow the
// per-endpoint parameter cap. Associative string keys (filters[category]) are
// kept — they are meaningful field names, not ids.
func NormalizeParamName(name string) string {
	if !strings.Contains(name, "[") {
		return name
	}
	return paramIndexRE.ReplaceAllStringFunc(name, func(b string) string {
		inner := b[1 : len(b)-1]
		if inner == "" || variableIndex(inner) {
			return "[]"
		}
		return b
	})
}

// variableIndex reports whether a bracket's contents look like an identifier
// (a number, uuid, hash, date) rather than a stable named key.
func variableIndex(s string) bool {
	switch Infer(s) {
	case TypeInt, TypeFloat, TypeUUID, TypeHex, TypeDate:
		return true
	default:
		return false
	}
}

// Normalize maps a concrete request path onto the scope's template space,
// recording the observation. It returns the template segments and whether this
// observation triggered a new collapse (in which case the caller must
// re-normalize its existing endpoints — see Renormalize).
func (e *Engine) Normalize(path string) (segs []string, collapsed bool) {
	raw := SplitPath(path)
	norm := make([]string, 0, len(raw))
	for _, seg := range raw {
		prefix := strings.Join(norm, "/")
		if t, ok := e.collapses[prefix]; ok && Matches(seg, t) {
			norm = append(norm, Token(t))
			continue
		}
		if e.observe(prefix, seg) {
			collapsed = true
			// The collapse we just created may apply to this very segment — but
			// only if the segment matches: a literal like "search" can be the
			// observation that tips a position to {int}, and stamping IT with
			// the token would fold a literal route into the parameter.
			if t := e.collapses[prefix]; Matches(seg, t) {
				norm = append(norm, Token(t))
				continue
			}
		}
		norm = append(norm, seg)
	}
	return norm, collapsed
}

// Renormalize maps an EXISTING template through the current collapse set
// without recording anything. Parameter tokens pass through unchanged; literal
// segments that now sit under a matching collapse become parameters. This is
// how a new collapse merges its previously-literal siblings.
func (e *Engine) Renormalize(template string) string {
	raw := SplitPath(template)
	norm := make([]string, 0, len(raw))
	for _, seg := range raw {
		if _, isTok := ParseToken(seg); isTok {
			norm = append(norm, seg)
			continue
		}
		prefix := strings.Join(norm, "/")
		if t, ok := e.collapses[prefix]; ok && Matches(seg, t) {
			norm = append(norm, Token(t))
			continue
		}
		norm = append(norm, seg)
	}
	return JoinTemplate(norm)
}

// LearnTemplate seeds the collapse set from a stored template, so a restart
// resumes the learned decisions instead of re-deriving them. Monotonicity
// depends on this: a decision, once made, survives the process.
func (e *Engine) LearnTemplate(template string) {
	segs := SplitPath(template)
	prefixSegs := make([]string, 0, len(segs))
	for _, seg := range segs {
		if t, isTok := ParseToken(seg); isTok {
			prefix := strings.Join(prefixSegs, "/")
			if existing, ok := e.collapses[prefix]; ok {
				e.collapses[prefix] = Join(existing, t)
			} else {
				e.collapses[prefix] = t
			}
		}
		prefixSegs = append(prefixSegs, seg)
	}
}

// observe records one value at one position and reports whether it caused the
// position to collapse.
func (e *Engine) observe(prefix, value string) bool {
	st := e.stats[prefix]
	if st == nil {
		st = &segStat{values: map[string]int{}, typeCounts: map[ValueType]int{}}
		e.stats[prefix] = st
	}
	st.count++
	st.typeCounts[Infer(value)]++
	// Always count a value already tracked, even after overflow: its repetition
	// is the signal that separates a route (hit again and again) from an id
	// (seen once). Only the DISTINCT set stops growing at the cap.
	if _, seen := st.values[value]; seen {
		st.values[value]++
	} else if len(st.values) <= e.opts.MaxDistinct {
		st.values[value]++
	} else {
		// One past the cap: the true distinct count exceeds what we hold.
		st.overflow = true
	}

	if st.count < e.opts.MinSamples {
		return false
	}

	distinct := len(st.values)
	if st.overflow {
		distinct = e.opts.MaxDistinct + 1
	}

	// A typed collapse is preferred: {int} says more than {var} and does not
	// swallow literal siblings of other shapes.
	if distinct >= e.opts.MinDistinctForType {
		if t, ok := e.dominantType(st); ok {
			e.collapse(prefix, t)
			return true
		}
	}
	if distinct > e.opts.MaxDistinct &&
		st.count >= e.opts.MaxDistinct*e.opts.VarRepeatFactor &&
		e.variableEnough(st) {
		e.collapse(prefix, TypeVar)
		return true
	}
	return false
}

// variableEnough decides the ambiguous case — a position past MaxDistinct with
// no dominant type. Repetition is the discriminator: an identifier space almost
// never repeats a value, while a route vocabulary is hit again and again. It
// collapses to {var} only when the tracked values are mostly still singletons;
// a repeating set of literals stays distinct routes, bounded by the per-host
// endpoint cap rather than by cardinality.
func (e *Engine) variableEnough(st *segStat) bool {
	if e.opts.VarSingletonShare <= 0 || len(st.values) == 0 {
		return true
	}
	singletons := 0
	for _, c := range st.values {
		if c == 1 {
			singletons++
		}
	}
	return float64(singletons)/float64(len(st.values)) >= e.opts.VarSingletonShare
}

// dominantType returns the promotable type covering at least TypeShare of the
// observations at a position, if one exists.
func (e *Engine) dominantType(st *segStat) (ValueType, bool) {
	// Deterministic iteration: sort candidate types so map order can never
	// influence which qualifying type wins.
	types := make([]ValueType, 0, len(st.typeCounts))
	for t := range st.typeCounts {
		types = append(types, t)
	}
	sort.Slice(types, func(i, j int) bool { return types[i] < types[j] })
	for _, t := range types {
		if !promotable(t) {
			continue
		}
		if float64(st.typeCounts[t]) >= e.opts.TypeShare*float64(st.count) {
			return t, true
		}
	}
	return "", false
}

// collapse records the decision and re-keys every deeper statistic so that
// evidence gathered under /job/8584286/... continues under /job/{int}/...
// instead of being lost.
func (e *Engine) collapse(prefix string, t ValueType) {
	e.collapses[prefix] = t
	delete(e.stats, prefix)

	tokenSeg := Token(t)
	rekey := func(old string) (string, bool) {
		rest, found := strings.CutPrefix(old, prefix+"/")
		if !found && prefix != "" {
			return "", false
		}
		if prefix == "" {
			rest = old
		}
		if rest == "" {
			return "", false
		}
		restSegs := strings.SplitN(rest, "/", 2)
		if !Matches(restSegs[0], t) {
			return "", false // a literal sibling; its subtree stays its own
		}
		newKey := tokenSeg
		if prefix != "" {
			newKey = prefix + "/" + tokenSeg
		}
		if len(restSegs) == 2 {
			newKey += "/" + restSegs[1]
		}
		return newKey, true
	}

	// Collect first, mutate after: inserting into a map while ranging over it
	// is unspecified, and the re-keying below does both.
	type statMove struct {
		old, new string
		st       *segStat
	}
	var statMoves []statMove
	for old, st := range e.stats {
		if newKey, ok := rekey(old); ok {
			statMoves = append(statMoves, statMove{old, newKey, st})
		}
	}
	// Deterministic order so merged caps do not depend on map iteration.
	sort.Slice(statMoves, func(i, j int) bool { return statMoves[i].old < statMoves[j].old })
	for _, m := range statMoves {
		delete(e.stats, m.old)
		e.mergeStat(m.new, m.st)
	}

	type collapseMove struct {
		old, new string
		t        ValueType
	}
	var collapseMoves []collapseMove
	for old, ct := range e.collapses {
		if old == prefix {
			continue
		}
		if newKey, ok := rekey(old); ok {
			collapseMoves = append(collapseMoves, collapseMove{old, newKey, ct})
		}
	}
	sort.Slice(collapseMoves, func(i, j int) bool { return collapseMoves[i].old < collapseMoves[j].old })
	for _, m := range collapseMoves {
		delete(e.collapses, m.old)
		if existing, exists := e.collapses[m.new]; exists {
			e.collapses[m.new] = Join(existing, m.t)
		} else {
			e.collapses[m.new] = m.t
		}
	}
}

func (e *Engine) mergeStat(key string, in *segStat) {
	st := e.stats[key]
	if st == nil {
		e.stats[key] = in
		return
	}
	st.count += in.count
	st.overflow = st.overflow || in.overflow
	for t, n := range in.typeCounts {
		st.typeCounts[t] += n
	}
	for v, n := range in.values {
		if _, seen := st.values[v]; seen || len(st.values) <= e.opts.MaxDistinct {
			st.values[v] += n
		} else {
			st.overflow = true
		}
	}
}
