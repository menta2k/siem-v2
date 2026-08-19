// Package group assembles records into correlated request flows.
package group

import (
	"sort"

	"github.com/menta2k/siem-v2/backend/internal/correlate/keys"
)

// Record is the minimal view of an event that grouping needs.
type Record struct {
	// EventID identifies the record itself.
	EventID string
	// Provider is used to judge whether a component spans more than one source.
	Provider string
	// Identifiers are ALL per-request ids this record carries. A record with two
	// identifiers bridges two identifier spaces.
	Identifiers []keys.Identifier
}

// Component is a set of records joined at exact tier.
type Component struct {
	// Key is the deterministic canonical id of the component.
	Key keys.Key
	// EventIDs are the records in the component, in stable order.
	EventIDs []string
	// Providers are the distinct providers represented, sorted.
	Providers []string
	// Bridged is true when the component was only connected because some record
	// carried more than one identifier. This is what makes a DataDome record
	// reachable from an nginx record, and it is worth surfacing: it means the
	// join depended on the Cloudflare custom-field capture being configured.
	Bridged bool
}

// Exact groups records into components by shared identifiers, unioning
// transitively.
//
// The transitive part is the whole point. A DataDome record knows only its own
// requestid and an nginx line knows only the ray id; they share nothing directly.
// The Cloudflare record carries both, so unioning over identifier sets connects
// all three — at exact tier, with no dependence on clock agreement.
//
// Records carrying no usable identifier are not returned here; they fall through
// to the heuristic tier.
func Exact(records []Record) []Component {
	uf := newUnionFind()

	// Link every identifier a record carries to that record's first identifier.
	// This is where bridging happens: the record acts as the edge between its own
	// identifiers, whether or not any other record knows both.
	for _, r := range records {
		ids := r.Identifiers
		if len(ids) == 0 {
			continue
		}
		first := ids[0].String()
		uf.add(first)
		for _, id := range ids[1:] {
			uf.link(first, id.String())
		}
	}

	type acc struct {
		ids       map[string]bool
		eventIDs  []string
		providers map[string]bool
		bridged   bool
	}
	byRoot := map[string]*acc{}

	for _, r := range records {
		if len(r.Identifiers) == 0 {
			continue
		}
		root := uf.find(r.Identifiers[0].String())
		a := byRoot[root]
		if a == nil {
			a = &acc{ids: map[string]bool{}, providers: map[string]bool{}}
			byRoot[root] = a
		}
		a.eventIDs = append(a.eventIDs, r.EventID)
		a.providers[r.Provider] = true
		for _, id := range r.Identifiers {
			a.ids[id.String()] = true
		}
		// A record contributing more than one identifier is the bridge.
		if len(r.Identifiers) > 1 {
			a.bridged = true
		}
	}

	components := make([]Component, 0, len(byRoot))
	for _, a := range byRoot {
		ids := make([]keys.Identifier, 0, len(a.ids))
		for s := range a.ids {
			ids = append(ids, parseIdentifier(s))
		}
		canonical, ok := keys.Canonical(ids)
		if !ok {
			continue
		}
		providers := make([]string, 0, len(a.providers))
		for p := range a.providers {
			providers = append(providers, p)
		}
		sort.Strings(providers)
		sort.Strings(a.eventIDs)

		components = append(components, Component{
			Key: keys.Key{
				Value:   canonical,
				Tier:    keys.TierExact,
				Signals: []keys.Signal{keys.SignalVendorRequestID},
			},
			EventIDs:  a.eventIDs,
			Providers: providers,
			// Bridging only *matters* when the component actually spans providers;
			// a single-provider component with two ids joined nothing extra.
			Bridged: a.bridged && len(providers) > 1,
		})
	}

	// Stable output so reprocessing yields identical results (FR-022).
	sort.Slice(components, func(i, j int) bool {
		return components[i].Key.Value < components[j].Key.Value
	})
	return components
}

// parseIdentifier reverses Identifier.String(). Splitting on the first colon is
// correct because namespaces are fixed constants without colons, while values
// may contain them.
func parseIdentifier(s string) keys.Identifier {
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			return keys.Identifier{Namespace: s[:i], Value: s[i+1:]}
		}
	}
	return keys.Identifier{Value: s}
}
