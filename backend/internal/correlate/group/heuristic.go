package group

import (
	"sort"
	"strings"
	"time"

	"github.com/menta2k/siem-v2/backend/internal/correlate/keys"
)

// HeuristicRecord is a record that carried no usable identifier and can only be
// joined on attributes and time proximity.
type HeuristicRecord struct {
	EventID   string
	Provider  string
	ClientIP  string
	Host      string
	Path      string
	Method    string
	EventTime time.Time
}

// HeuristicOptions bounds the fallback join.
type HeuristicOptions struct {
	// Window is the maximum time separation between records of the same request.
	// It must stay small: every millisecond of width increases the chance of
	// merging two genuinely different requests from the same client.
	Window time.Duration
}

// Heuristic groups records that share client, host, path and method within a
// bounded time window.
//
// This tier exists because identifier propagation is not universal — F5 in
// particular may not be able to log CF-Ray (verification item V2). It is a
// fallback, not a peer of the exact tier, and it is deliberately conservative:
//
//   - A candidate set containing two records from the SAME provider is ambiguous,
//     because one request cannot produce two records at one layer. Rather than
//     pick one, the whole set is reported ambiguous and left unjoined (FR-021).
//   - Records missing any part of the attribute key are not joined at all. A
//     partial key would match far too much.
func Heuristic(records []HeuristicRecord, opts HeuristicOptions) (components []Component, ambiguous []string) {
	window := opts.Window
	if window <= 0 {
		window = 5 * time.Second
	}

	byKey := map[string][]HeuristicRecord{}
	for _, r := range records {
		key, ok := attributeKey(r)
		if !ok {
			// Not enough to join on. The record stays searchable but uncorrelated.
			continue
		}
		byKey[key] = append(byKey[key], r)
	}

	keysSorted := make([]string, 0, len(byKey))
	for k := range byKey {
		keysSorted = append(keysSorted, k)
	}
	sort.Strings(keysSorted)

	for _, k := range keysSorted {
		bucket := byKey[k]
		sort.SliceStable(bucket, func(i, j int) bool {
			if !bucket[i].EventTime.Equal(bucket[j].EventTime) {
				return bucket[i].EventTime.Before(bucket[j].EventTime)
			}
			return bucket[i].EventID < bucket[j].EventID
		})

		for _, cluster := range clusterByTime(bucket, window) {
			if len(cluster) < 2 {
				continue // nothing joined
			}
			if dup, providers := hasDuplicateProvider(cluster); dup {
				// Two records from one layer means we cannot tell which belongs to
				// which request. Guessing here is exactly the failure a SIEM must
				// not make, so the set is reported and left unjoined.
				for _, r := range cluster {
					ambiguous = append(ambiguous, r.EventID)
				}
				_ = providers
				continue
			}
			components = append(components, buildHeuristicComponent(cluster))
		}
	}

	sort.Strings(ambiguous)
	sort.Slice(components, func(i, j int) bool {
		return components[i].Key.Value < components[j].Key.Value
	})
	return components, ambiguous
}

// clusterByTime splits a bucket into runs whose consecutive records are within
// the window of each other.
func clusterByTime(bucket []HeuristicRecord, window time.Duration) [][]HeuristicRecord {
	var out [][]HeuristicRecord
	current := []HeuristicRecord{bucket[0]}
	for i := 1; i < len(bucket); i++ {
		if bucket[i].EventTime.Sub(current[len(current)-1].EventTime) <= window {
			current = append(current, bucket[i])
			continue
		}
		out = append(out, current)
		current = []HeuristicRecord{bucket[i]}
	}
	return append(out, current)
}

func hasDuplicateProvider(cluster []HeuristicRecord) (bool, []string) {
	seen := map[string]bool{}
	var providers []string
	for _, r := range cluster {
		if seen[r.Provider] {
			return true, providers
		}
		seen[r.Provider] = true
		providers = append(providers, r.Provider)
	}
	return false, providers
}

func buildHeuristicComponent(cluster []HeuristicRecord) Component {
	eventIDs := make([]string, 0, len(cluster))
	providerSet := map[string]bool{}
	for _, r := range cluster {
		eventIDs = append(eventIDs, r.EventID)
		providerSet[r.Provider] = true
	}
	sort.Strings(eventIDs)

	providers := make([]string, 0, len(providerSet))
	for p := range providerSet {
		providers = append(providers, p)
	}
	sort.Strings(providers)

	return Component{
		// The smallest event id is the canonical key, keeping flow identity
		// deterministic for heuristic joins too (FR-022).
		Key: keys.Key{
			Value:   "heur:" + eventIDs[0],
			Tier:    keys.TierHeuristic,
			Signals: []keys.Signal{keys.SignalIPHostPathMethod, keys.SignalTimeWindow},
		},
		EventIDs:  eventIDs,
		Providers: providers,
	}
}

// attributeKey builds the join key, requiring every component to be present.
func attributeKey(r HeuristicRecord) (string, bool) {
	if r.ClientIP == "" || r.Host == "" || r.Path == "" || r.Method == "" || r.EventTime.IsZero() {
		return "", false
	}
	return strings.Join([]string{r.ClientIP, r.Host, r.Path, strings.ToUpper(r.Method)}, "|"), true
}
