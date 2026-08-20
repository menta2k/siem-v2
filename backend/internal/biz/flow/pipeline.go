package flow

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/menta2k/siem-v2/backend/internal/correlate/group"
	"github.com/menta2k/siem-v2/backend/internal/correlate/keys"
	"github.com/menta2k/siem-v2/backend/internal/correlate/window"
	"github.com/menta2k/siem-v2/backend/internal/ingest"
	"github.com/menta2k/siem-v2/backend/internal/ingest/filter"
	"github.com/menta2k/siem-v2/backend/internal/normalize"
	"github.com/menta2k/siem-v2/backend/internal/normalize/schema"
)

// Store persists completed flows.
type Store interface {
	Store(ctx context.Context, f *Flow) error
	// StoreRaw persists the unmodified originals of ONE batch in one call.
	// One insert per record capped the whole pipeline at the HTTP round-trip
	// rate (~370 records/s observed) while CPU sat idle.
	StoreRaw(ctx context.Context, tenant string, provider schema.Provider,
		items []RawItem, receivedAt time.Time) error
}

// Pipeline turns buffered raw batches into stored flows.
//
// The stages are deliberately separable — parse, correlate, materialize, store —
// because each fails differently and the constitution requires each to be
// observable on its own.
type Pipeline struct {
	Parsers    map[schema.Provider]normalize.Parser
	Window     *window.Window
	Store      Store
	DeadLetter ingest.DeadLetter
	Now        func() time.Time
	// ExpectedLayers is the request path this deployment monitors. The window's
	// early-close count and the flow's completeness verdict MUST agree on it, or
	// a flow the window closed as "all layers present" materializes as partial.
	ExpectedLayers []schema.Layer
	// Masker classifies and masks sensitive fields BEFORE anything is written.
	// Masking at read time would leave the secret sitting in storage, readable by
	// anyone with database access, for the whole retention period (FR-015).
	Masker *normalize.Masker

	// OnFlow is called for each completed flow, letting the caller record metrics
	// or evaluate detections without this package depending on either.
	OnFlow func(*Flow)
	// OnParseFailure is called for each dead-lettered record.
	OnParseFailure func(schema.Provider, error)

	// Filters resolves a tenant's ingest filter rules (nil = keep everything).
	// A matched record is dropped BEFORE anything is stored: no raw payload,
	// no event, no flow — the one deliberate exception to Constitution II,
	// and the reason resolution failures upstream fail OPEN.
	Filters func(tenant string) *filter.Set
	// OnFiltered observes drops for counting/logging.
	OnFiltered func(tenant string, provider schema.Provider, count int)

	// Loader, when set, lets a closing flow MERGE with one already stored
	// under the same correlation key instead of duplicating it. This is what
	// joins a batch-delivered provider (Logpush, minutes late) to a real-time
	// one (Vector, seconds) when the gap exceeds the window: the Amender's
	// semantics — one late-corrected flow beats two flows for one request
	// (FR-018) — finally wired into the write path.
	Loader FlowLoader

	// mu guards events, records and bridged. ProcessBatch runs on the buffer
	// consumer's goroutine while Correlate and Flush run on the flush ticker's,
	// and the two met for the first time at 24k events/sec as a fatal
	// "concurrent map read and map write" — a crash the load test exists to
	// find before production traffic does.
	mu sync.Mutex
	// recentKeys remembers correlation keys stored within the merge horizon,
	// so the amend path costs one point-read ONLY for genuine latecomers
	// rather than for every closing flow. Its own mutex: it is touched during
	// storage, which deliberately runs OUTSIDE p.mu.
	recentMu   sync.Mutex
	recentKeys map[string]time.Time
	// events holds parsed events awaiting correlation, keyed by event id.
	events map[string]schema.Event
	// identifiers holds each event's identifier set for grouping.
	records []group.Record
	// bridged remembers, per correlation key, whether the component was only
	// connected because some record carried more than one identifier. Grouping
	// knows this but the window does not, so without carrying it here the fact
	// that a flow depended on the Cloudflare custom-field capture is lost by the
	// time the flow is materialized.
	bridged map[string]bool
}

func NewPipeline(store Store, dl ingest.DeadLetter, w *window.Window) *Pipeline {
	return &Pipeline{
		Parsers:    map[schema.Provider]normalize.Parser{},
		Window:     w,
		Store:      store,
		DeadLetter: dl,
		Now:        func() time.Time { return time.Now().UTC() },
		events:     map[string]schema.Event{},
		bridged:    map[string]bool{},
	}
}

// Register adds a parser for a provider.
func (p *Pipeline) Register(parser normalize.Parser) {
	p.Parsers[parser.Provider()] = parser
}

// ProcessBatch parses a raw batch and accumulates its events for correlation.
//
// A parse failure never fails the batch: the bad record is dead-lettered with
// its original bytes and the rest continue. One provider changing its format
// must not stop the other three from being processed (FR-012).
func (p *Pipeline) ProcessBatch(ctx context.Context, batch ingest.RawBatch) error {
	parser, ok := p.Parsers[batch.Provider]
	if !ok {
		return fmt.Errorf("no parser registered for provider %q", batch.Provider)
	}

	var filters *filter.Set
	if p.Filters != nil {
		filters = p.Filters(batch.Tenant)
	}

	// Parse first, THEN store: the filter needs the normalized host/path, and
	// a filtered record must never be stored anywhere. Kept records' originals
	// still go in one bulk call (Constitution II for everything we ingest);
	// parse failures keep their originals in the dead letter.
	kept := make([]RawItem, 0, len(batch.Records))
	events := make([]schema.Event, 0, len(batch.Records))
	filtered := 0
	for _, raw := range batch.Records {
		event, err := parser.Parse(raw, batch.ReceivedAt)
		if err != nil {
			p.deadLetter(ctx, batch, raw, parser, err)
			continue
		}
		if filters.Drops(event.Request.Host, event.Request.Path) {
			filtered++
			continue
		}
		event.Tenant = batch.Tenant
		kept = append(kept, RawItem{
			ID: fmt.Sprintf("%s:%s", batch.Provider, hashOf(raw)), Payload: raw,
		})
		events = append(events, *event)
	}
	if filtered > 0 && p.OnFiltered != nil {
		p.OnFiltered(batch.Tenant, batch.Provider, filtered)
	}
	if p.Store != nil && len(kept) > 0 {
		_ = p.Store.StoreRaw(ctx, batch.Tenant, batch.Provider, kept, batch.ReceivedAt)
	}
	for i := range events {
		if p.Masker != nil {
			p.Masker.Apply(&events[i])
		}
		p.accumulate(events[i], batch.ReceivedAt)
	}
	return nil
}

func (p *Pipeline) deadLetter(ctx context.Context, batch ingest.RawBatch, raw []byte,
	parser normalize.Parser, err error) {
	if p.OnParseFailure != nil {
		p.OnParseFailure(batch.Provider, err)
	}
	if p.DeadLetter == nil {
		return
	}
	_ = p.DeadLetter.Put(ctx, ingest.DeadLetterRecord{
		DLID:           "dl:" + hashOf(raw),
		SourceID:       batch.SourceID,
		Tenant:         batch.Tenant,
		Provider:       batch.Provider,
		Payload:        raw, // ORIGINAL bytes, so a parser fix can reprocess later
		FailureReason:  err.Error(),
		ParserVersion:  parser.Version(),
		ReceivedAt:     batch.ReceivedAt,
		ReprocessState: ingest.ReprocessPending,
	})
}

// accumulate records an event for later grouping.
func (p *Pipeline) accumulate(e schema.Event, at time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, seen := p.events[e.EventID]; seen {
		return // idempotent: redelivery must not duplicate a layer (FR-007)
	}
	p.events[e.EventID] = e

	ids := make([]keys.Identifier, 0, len(e.Identifiers))
	for _, s := range e.Identifiers {
		ids = append(ids, parseIdentifier(s))
	}
	p.records = append(p.records, group.Record{
		EventID: e.EventID, Provider: string(e.Provider), Identifiers: ids,
	})
}

// Correlate groups accumulated events and feeds them into the window.
func (p *Pipeline) Correlate() {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.Now()
	for _, component := range group.Exact(p.records) {
		if component.Bridged {
			p.bridged[component.Key.Value] = true
		}
		for _, id := range component.EventIDs {
			e, ok := p.events[id]
			if !ok {
				continue
			}
			p.Window.Add(component.Key.Value, e.Tenant, e, now)
		}
	}
	// Accumulated records have been handed to the window; clearing here keeps
	// memory bounded per cycle rather than growing for the process lifetime.
	p.records = p.records[:0]
}

// Flush materializes and stores every flow whose window has closed.
//
// The lock covers ONLY the in-memory bookkeeping. Storage runs outside it:
// a catch-up burst once closed 200k windows in one tick, and storing them
// under the mutex froze the consumer (accumulate takes the same lock) for
// the whole write — the acks stopped and the backlog regrew.
func (p *Pipeline) Flush(ctx context.Context) (int, error) {
	p.mu.Lock()
	now := p.Now()
	ready := p.Window.Ready(now)

	flows := make([]*Flow, 0, len(ready))
	for _, state := range ready {
		f := Materialize(state.CorrelationKey, state.Events, Options{
			Tenant:         state.Tenant,
			Method:         methodFor(state.CorrelationKey),
			Bridged:        p.bridged[state.CorrelationKey],
			ExpectedLayers: p.ExpectedLayers,
			Closed:         true,
			Now:            now,
		})
		if f == nil {
			continue
		}
		f.Amended = state.Amended
		f.CorrelationKey = state.CorrelationKey
		flows = append(flows, f)

		for _, id := range collectEventIDs(state.Events) {
			delete(p.events, id)
		}
		delete(p.bridged, state.CorrelationKey)
	}
	p.mu.Unlock()

	stored := 0
	// Bulk-capable stores take large slices in few calls; per-flow inserts
	// are kept only as the fallback for stores without the capability.
	bulk, bulkOK := p.Store.(BulkStore)
	pending := make([]*Flow, 0, storeChunk)
	emit := func(fs []*Flow) error {
		if len(fs) == 0 {
			return nil
		}
		if bulkOK {
			if err := bulk.StoreFlows(ctx, fs); err != nil {
				return fmt.Errorf("store %d flows: %w", len(fs), err)
			}
		} else if p.Store != nil {
			for _, f := range fs {
				if err := p.Store.Store(ctx, f); err != nil {
					return fmt.Errorf("store flow %s: %w", f.FlowID, err)
				}
			}
		}
		p.recentMu.Lock()
		if p.recentKeys == nil {
			p.recentKeys = map[string]time.Time{}
		}
		for _, f := range fs {
			p.recentKeys[f.CorrelationKey] = now
		}
		p.pruneRecentKeys(now)
		p.recentMu.Unlock()
		if p.OnFlow != nil {
			for _, f := range fs {
				p.OnFlow(f)
			}
		}
		return nil
	}

	for _, f := range flows {
		if p.Loader != nil {
			p.recentMu.Lock()
			_, seen := p.recentKeys[f.CorrelationKey]
			p.recentMu.Unlock()
			if seen {
				if merged := p.mergeWithStored(ctx, f.Tenant, f.CorrelationKey, f, now); merged != nil {
					merged.CorrelationKey = f.CorrelationKey
					f = merged
				}
			}
		}
		pending = append(pending, f)
		if len(pending) >= storeChunk {
			if err := emit(pending); err != nil {
				return stored, err
			}
			stored += len(pending)
			pending = pending[:0]
		}
	}
	if err := emit(pending); err != nil {
		return stored, err
	}
	stored += len(pending)
	return stored, nil
}

// storeChunk bounds one bulk insert; large enough to amortize the round
// trip, small enough that one call's payload stays reasonable.
const storeChunk = 500

// BulkStore is the optional fast path: stores that can persist many flows
// per call implement it; the pipeline falls back to per-flow Store otherwise.
type BulkStore interface {
	StoreFlows(ctx context.Context, flows []*Flow) error
}

// methodFor infers the join tier from the correlation key's shape. Heuristic
// keys are prefixed at construction, so the distinction survives into storage.
func methodFor(correlationKey string) keys.Tier {
	if strings.HasPrefix(correlationKey, "heur:") {
		return keys.TierHeuristic
	}
	return keys.TierExact
}

func collectEventIDs(events []schema.Event) []string {
	out := make([]string, 0, len(events))
	for _, e := range events {
		out = append(out, e.EventID)
	}
	return out
}

func parseIdentifier(s string) keys.Identifier {
	if i := strings.IndexByte(s, ':'); i >= 0 {
		return keys.Identifier{Namespace: s[:i], Value: s[i+1:]}
	}
	return keys.Identifier{Value: s}
}

func hashOf(b []byte) string {
	const prime = 1099511628211
	var h uint64 = 14695981039346656037
	for _, c := range b {
		h ^= uint64(c)
		h *= prime
	}
	return fmt.Sprintf("%016x", h)
}

// InFlight reports how many flows are open, a bounded-memory signal.
func (p *Pipeline) InFlight() int { return p.Window.InFlight() }

// Snapshot drains accumulated events into the window and returns the whole
// in-flight state for persistence (FR-023). Called on graceful shutdown so a
// restart resumes rather than discarding partial flows.
func (p *Pipeline) Snapshot() []*window.State {
	p.Correlate() // move any events still in p.events into the window first
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.Window.Snapshot()
}

// Restore reinstates a persisted window on startup.
func (p *Pipeline) Restore(states []*window.State) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.Window.Restore(states)
}

// RawItem is one original record queued for raw storage.
type RawItem struct {
	ID      string
	Payload []byte
}

// mergeHorizon bounds how long a stored flow stays mergeable. Beyond it a
// straggler opens a duplicate flow — the pre-merge behavior — rather than
// this map growing without bound.
const mergeHorizon = time.Hour

// mergeWithStored folds a straggler flow into its stored predecessor.
// Returns nil when there is nothing to merge with, and never fails the flush:
// a duplicate flow beats a lost one.
func (p *Pipeline) mergeWithStored(ctx context.Context, tenant, key string, late *Flow, now time.Time) *Flow {
	existing, err := p.Loader.Get(ctx, tenant, late.FlowID)
	if err != nil || existing == nil {
		return nil
	}
	seen := map[string]bool{}
	events := make([]schema.Event, 0, len(existing.Events)+len(late.Events))
	for _, e := range existing.Events {
		if !seen[e.EventID] {
			seen[e.EventID] = true
			events = append(events, e)
		}
	}
	added := false
	for _, e := range late.Events {
		if !seen[e.EventID] {
			seen[e.EventID] = true
			events = append(events, e)
			added = true
		}
	}
	if !added {
		return existing
	}
	merged := Materialize(key, events, Options{
		Tenant:         tenant,
		Method:         existing.Method,
		Bridged:        existing.Bridged || late.Bridged,
		ExpectedLayers: p.ExpectedLayers,
		Closed:         true,
		Now:            now,
	})
	if merged == nil {
		return nil
	}
	// The change is marked, never hidden: a flow that grew after someone may
	// have looked at it is something they need to know (FR-018).
	merged.Amended = true
	return merged
}

func (p *Pipeline) pruneRecentKeys(now time.Time) {
	// Amortized: prune only when the map is large, scanning once.
	if len(p.recentKeys) < 500000 {
		return
	}
	for k, at := range p.recentKeys {
		if now.Sub(at) > mergeHorizon {
			delete(p.recentKeys, k)
		}
	}
}
