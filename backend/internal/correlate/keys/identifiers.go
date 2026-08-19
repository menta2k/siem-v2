// Package keys extracts the per-request identifiers a record carries and models
// how records are keyed for correlation.
//
// The central idea, and the reason this package exists separately from the
// grouping logic: a record carries a SET of identifiers, not one. Reading "join
// on a shared id" literally — picking one id per record — makes bridging
// impossible and quietly pushes every cross-vendor join into the heuristic tier.
package keys

import (
	"sort"
	"strings"
)

// Tier records how confidently a set of records was joined.
type Tier string

const (
	// TierExact means the records share an identifier, directly or transitively.
	// No clock agreement is involved, so there is no false-join risk.
	TierExact Tier = "exact"
	// TierHeuristic means the records matched on attributes and time proximity.
	TierHeuristic Tier = "heuristic"
	// TierNone means no join was possible; the record stands alone.
	TierNone Tier = "none"
)

// Signal names what evidence produced a join, so the UI can explain it.
type Signal string

const (
	SignalVendorRequestID  Signal = "vendor_request_id"
	SignalIPHostPathMethod Signal = "ip_host_path_method"
	SignalTimeWindow       Signal = "time_window"
)

// Key identifies the group a record belongs to.
type Key struct {
	Value   string
	Tier    Tier
	Signals []Signal
}

// Namespaced identifiers keep two providers' id spaces from colliding. A
// DataDome requestid and a Cloudflare ray id are both opaque strings; without a
// namespace, an unlikely-but-possible collision would silently merge two
// unrelated requests, which is exactly the kind of wrong answer a SIEM must not
// produce.
const (
	NSRayID    = "ray"
	NSDataDome = "dd"
	NSF5       = "f5"
)

// Identifier is one namespaced per-request id.
type Identifier struct {
	Namespace string
	Value     string
}

// String renders the identifier in its canonical "ns:value" form. This is the
// form used for union-find membership and for the canonical group id.
func (i Identifier) String() string { return i.Namespace + ":" + i.Value }

// NewIdentifier normalizes and validates a raw identifier value. It returns
// false for values that must not be used as join keys.
func NewIdentifier(ns, value string) (Identifier, bool) {
	v := strings.TrimSpace(value)
	if v == "" {
		return Identifier{}, false
	}
	// Providers write absent values in several ways; joining on any of these
	// would merge every record that happens to be missing the field.
	switch strings.ToLower(v) {
	case "-", "na", "n/a", "null", "nil", "none", "unknown", "0":
		return Identifier{}, false
	}
	return Identifier{Namespace: ns, Value: v}, true
}

// Canonical returns the deterministic representative of an identifier set: the
// lexicographically smallest member.
//
// Determinism matters more than it looks. The same set of records must produce
// the same flow identity however they were discovered or ordered, otherwise
// reprocessing produces different flow ids and FR-022 fails.
func Canonical(ids []Identifier) (string, bool) {
	if len(ids) == 0 {
		return "", false
	}
	strs := make([]string, 0, len(ids))
	for _, id := range ids {
		strs = append(strs, id.String())
	}
	sort.Strings(strs)
	return strs[0], true
}
