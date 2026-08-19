// Package correlate assembles normalized events into ordered request flows.
package correlate

import (
	"sort"

	"github.com/menta2k/siem-v2/backend/internal/normalize/schema"
)

// OrderEvents returns the events of one flow in causal order.
//
// Ordering derives from each event's LAYER, not its timestamp. This is the
// single most important decision in this file: provider clocks disagree, often
// by seconds, and sorting by timestamp produces flows where the origin appears
// to have served a request before the edge received it. The request path is
// known — edge, then bot management, then application firewall, then origin — so
// we order by that and treat disagreeing timestamps as a data-quality signal
// rather than as evidence about ordering (FR-017).
//
// Within a layer, timestamp is a reasonable tiebreak: two events at the same
// layer come from the same clock, so their relative order is trustworthy. Event
// id breaks remaining ties so the result is deterministic (FR-022).
func OrderEvents(events []schema.Event) []schema.Event {
	ordered := make([]schema.Event, len(events))
	copy(ordered, events)

	sort.SliceStable(ordered, func(i, j int) bool {
		oi, ki := ordered[i].Layer.Order()
		oj, kj := ordered[j].Layer.Order()

		// An unknown layer has no defined position. Sorting it into the middle
		// would assert a causal claim we cannot support, so unknown layers sort
		// last where they are visibly unplaced rather than silently misplaced.
		switch {
		case ki && !kj:
			return true
		case !ki && kj:
			return false
		case ki && kj && oi != oj:
			return oi < oj
		}

		if !ordered[i].EventTime.Equal(ordered[j].EventTime) {
			return ordered[i].EventTime.Before(ordered[j].EventTime)
		}
		return ordered[i].EventID < ordered[j].EventID
	})

	return ordered
}

// DetectSkew reports whether the events' timestamps contradict their causal
// order, and by how much.
//
// A contradiction does not change the ordering — it is reported so an analyst
// can see that a provider's clock is wrong (FR-013). Returning the magnitude
// lets the caller distinguish millisecond jitter from a genuinely broken clock.
func DetectSkew(orderedEvents []schema.Event) (skewed bool, worstMS int64) {
	for i := 1; i < len(orderedEvents); i++ {
		prev, cur := orderedEvents[i-1], orderedEvents[i]
		if _, ok := prev.Layer.Order(); !ok {
			continue
		}
		if _, ok := cur.Layer.Order(); !ok {
			continue
		}
		// Same layer means same clock; disorder there is not skew between systems.
		if prev.Layer == cur.Layer {
			continue
		}
		if cur.EventTime.Before(prev.EventTime) {
			delta := prev.EventTime.Sub(cur.EventTime).Milliseconds()
			if delta > worstMS {
				worstMS = delta
			}
			skewed = true
		}
	}
	return skewed, worstMS
}
