// Package window manages in-flight correlation state and decides when a flow is
// finished.
//
// The core tension this package resolves: a flow cannot be declared complete the
// moment its first record arrives, because the other providers deliver on their
// own schedules; but it also cannot stay open forever, because in-flight state
// would grow without bound. The late-arrival window is the compromise, and
// everything here follows from it (FR-018, FR-019, FR-024).
package window

import (
	"sort"
	"time"

	"github.com/menta2k/siem-v2/backend/internal/normalize/schema"
)

// State is the accumulating state of one not-yet-closed flow.
type State struct {
	CorrelationKey string
	Tenant         string
	Events         []schema.Event
	FirstArrival   time.Time
	LastArrival    time.Time
	// Closed marks a flow whose window has elapsed. A closed flow can still be
	// amended by a very late record, but the amendment is marked (FR-018).
	Closed   bool
	ClosedAt time.Time
	Amended  bool
}

// Options configures the window.
type Options struct {
	// LateArrival bounds how long a flow waits for records that may never come.
	LateArrival time.Duration
	// ExpectedLayers is how many layers a complete flow has. Reaching it lets a
	// flow close early instead of waiting out the full window, which is what
	// keeps the common case fast.
	ExpectedLayers int
}

// Window accumulates events into flow states and reports which are ready.
//
// It holds no clock of its own: callers pass `now`. That keeps behaviour
// deterministic under test and, more importantly, makes replay reproducible —
// re-running the same records with the same timestamps produces the same closes.
type Window struct {
	opts   Options
	states map[string]*State
}

func New(opts Options) *Window {
	if opts.LateArrival <= 0 {
		opts.LateArrival = 15 * time.Minute
	}
	if opts.ExpectedLayers <= 0 {
		opts.ExpectedLayers = 4
	}
	return &Window{opts: opts, states: map[string]*State{}}
}

// Add records an event against its correlation key.
//
// Adding to an already-closed flow is legal and marks it amended rather than
// creating a second flow — showing an analyst two flows for one request would be
// worse than showing one late-corrected flow (FR-018).
func (w *Window) Add(key string, tenant string, e schema.Event, now time.Time) *State {
	st, ok := w.states[key]
	if !ok {
		st = &State{CorrelationKey: key, Tenant: tenant, FirstArrival: now}
		w.states[key] = st
	}
	// Idempotent: redelivery of the same event must not duplicate a layer.
	for _, existing := range st.Events {
		if existing.EventID == e.EventID {
			return st
		}
	}
	st.Events = append(st.Events, e)
	st.LastArrival = now
	if st.Closed {
		st.Amended = true
	}
	return st
}

// Ready returns the flows that should now be materialized, removing them from
// in-flight state.
//
// Two conditions close a flow:
//   - every expected layer has reported, so waiting longer gains nothing;
//   - the late-arrival window has elapsed, so waiting longer is unbounded.
func (w *Window) Ready(now time.Time) []*State {
	var ready []*State
	for key, st := range w.states {
		if st.Closed {
			continue
		}
		switch {
		case w.hasAllLayers(st):
			st.Closed, st.ClosedAt = true, now
			ready = append(ready, st)
			delete(w.states, key)
		case now.Sub(st.FirstArrival) >= w.opts.LateArrival:
			st.Closed, st.ClosedAt = true, now
			ready = append(ready, st)
			delete(w.states, key)
		}
	}
	// Deterministic order so replay produces identical output.
	sort.Slice(ready, func(i, j int) bool {
		return ready[i].CorrelationKey < ready[j].CorrelationKey
	})
	return ready
}

// hasAllLayers reports whether every expected layer has produced a record.
func (w *Window) hasAllLayers(st *State) bool {
	seen := map[schema.Layer]bool{}
	for _, e := range st.Events {
		seen[e.Layer] = true
	}
	return len(seen) >= w.opts.ExpectedLayers
}

// InFlight reports how many flows are open. This is a bounded-memory signal: a
// number that climbs without settling means flows are not closing, which is an
// operational fault whether or not any individual flow looks wrong.
func (w *Window) InFlight() int { return len(w.states) }

// Get returns the in-flight state for a key, if any.
func (w *Window) Get(key string) (*State, bool) {
	st, ok := w.states[key]
	return st, ok
}

// Merge folds the src flow's events into dst and removes src. Used when a late
// bridging record reveals that two separately-keyed windows are actually the
// same request (the Cloudflare origin-fetch row shares the origin ray but is
// canonically keyed on the parent). Returns dst's state.
func (w *Window) Merge(dst, src string) *State {
	from, ok := w.states[src]
	if !ok || src == dst {
		return w.states[dst]
	}
	into, ok := w.states[dst]
	if !ok {
		// dst does not exist yet: re-key src as dst rather than copy.
		from.CorrelationKey = dst
		w.states[dst] = from
		delete(w.states, src)
		return from
	}
	for _, e := range from.Events {
		dup := false
		for _, x := range into.Events {
			if x.EventID == e.EventID {
				dup = true
				break
			}
		}
		if !dup {
			into.Events = append(into.Events, e)
		}
	}
	if from.FirstArrival.Before(into.FirstArrival) {
		into.FirstArrival = from.FirstArrival
	}
	if from.LastArrival.After(into.LastArrival) {
		into.LastArrival = from.LastArrival
	}
	if into.Closed {
		into.Amended = true
	}
	delete(w.states, src)
	return into
}

// Restore reinstates in-flight state after a restart. Correlation state is
// persisted precisely so a restart resumes rather than discarding partial flows
// (FR-023).
func (w *Window) Restore(states []*State) {
	for _, st := range states {
		if st == nil || st.CorrelationKey == "" {
			continue
		}
		w.states[st.CorrelationKey] = st
	}
}

// Snapshot returns the current in-flight states for persistence.
func (w *Window) Snapshot() []*State {
	out := make([]*State, 0, len(w.states))
	for _, st := range w.states {
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CorrelationKey < out[j].CorrelationKey
	})
	return out
}
