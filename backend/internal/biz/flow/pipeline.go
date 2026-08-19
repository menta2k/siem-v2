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
	"github.com/menta2k/siem-v2/backend/internal/normalize"
	"github.com/menta2k/siem-v2/backend/internal/normalize/schema"
)

// Store persists completed flows.
type Store interface {
	Store(ctx context.Context, f *Flow) error
	StoreRaw(ctx context.Context, tenant string, provider schema.Provider,
		rawID string, payload []byte, receivedAt time.Time) error
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

	// mu guards events, records and bridged. ProcessBatch runs on the buffer
	// consumer's goroutine while Correlate and Flush run on the flush ticker's,
	// and the two met for the first time at 24k events/sec as a fatal
	// "concurrent map read and map write" — a crash the load test exists to
	// find before production traffic does.
	mu sync.Mutex
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

	for _, raw := range batch.Records {
		// The unmodified original is stored first, so it survives even if
		// everything downstream fails (Constitution II).
		rawID := fmt.Sprintf("%s:%s", batch.Provider, hashOf(raw))
		if p.Store != nil {
			_ = p.Store.StoreRaw(ctx, batch.Tenant, batch.Provider, rawID, raw, batch.ReceivedAt)
		}

		event, err := parser.Parse(raw, batch.ReceivedAt)
		if err != nil {
			p.deadLetter(ctx, batch, raw, parser, err)
			continue
		}
		event.Tenant = batch.Tenant
		if p.Masker != nil {
			p.Masker.Apply(event)
		}
		p.accumulate(*event, batch.ReceivedAt)

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
func (p *Pipeline) Flush(ctx context.Context) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.Now()
	ready := p.Window.Ready(now)

	stored := 0
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

		if p.Store != nil {
			if err := p.Store.Store(ctx, f); err != nil {
				return stored, fmt.Errorf("store flow %s: %w", f.FlowID, err)
			}
		}
		for _, id := range collectEventIDs(state.Events) {
			delete(p.events, id)
		}
		delete(p.bridged, state.CorrelationKey)
		if p.OnFlow != nil {
			p.OnFlow(f)
		}
		stored++
	}
	return stored, nil
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
