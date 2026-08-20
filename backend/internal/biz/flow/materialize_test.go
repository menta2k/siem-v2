package flow

import (
	"context"
	"testing"
	"time"

	"github.com/menta2k/siem-v2/backend/internal/correlate/window"
	"github.com/menta2k/siem-v2/backend/internal/ingest"
	"github.com/menta2k/siem-v2/backend/internal/normalize"

	"github.com/menta2k/siem-v2/backend/internal/correlate/keys"
	"github.com/menta2k/siem-v2/backend/internal/normalize/schema"
)

var base = time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)

func event(id string, layer schema.Layer, at time.Time, action schema.Action) schema.Event {
	return schema.Event{
		EventID: id, Layer: layer, EventTime: at,
		Verdict: schema.Verdict{Action: action, Terminating: action.Terminal(), Mapped: true},
	}
}

func opts(closed bool) Options {
	return Options{Tenant: "acme", Method: keys.TierExact, Now: base.Add(time.Minute), Closed: closed}
}

func TestCompleteFlowAcrossFourLayers(t *testing.T) {
	events := []schema.Event{
		event("cf", schema.LayerEdge, base, schema.ActionAllowed),
		event("dd", schema.LayerBotManagement, base.Add(time.Millisecond), schema.ActionAllowed),
		event("f5", schema.LayerAppFirewall, base.Add(2*time.Millisecond), schema.ActionAllowed),
		event("ngx", schema.LayerOrigin, base.Add(3*time.Millisecond), schema.ActionAllowed),
	}
	f := Materialize("ray:abc", events, opts(true))

	if f.Completeness != Complete {
		t.Errorf("all four layers present should be complete, got %q (missing=%v)", f.Completeness, f.LayersMissing)
	}
	if len(f.LayersMissing) != 0 {
		t.Errorf("no layers should be missing, got %v", f.LayersMissing)
	}
	if f.Confidence != 1.0 {
		t.Errorf("exact join is certain by construction, got %v", f.Confidence)
	}
	if f.FlowID != "flow:ray:abc" {
		t.Errorf("flow id must derive from the correlation key, got %q", f.FlowID)
	}
}

// TestMissingLayerIsNamedNotOmitted: "we never heard from the WAF" and "the WAF
// allowed it" are different facts and must never look the same.
func TestMissingLayerIsNamedNotOmitted(t *testing.T) {
	events := []schema.Event{
		event("cf", schema.LayerEdge, base, schema.ActionAllowed),
		event("ngx", schema.LayerOrigin, base.Add(3*time.Millisecond), schema.ActionAllowed),
	}
	f := Materialize("ray:abc", events, opts(true))

	if f.Completeness != Partial {
		t.Errorf("a closed flow with gaps is partial, got %q", f.Completeness)
	}
	want := map[schema.Layer]bool{schema.LayerBotManagement: true, schema.LayerAppFirewall: true}
	if len(f.LayersMissing) != 2 {
		t.Fatalf("expected two missing layers, got %v", f.LayersMissing)
	}
	for _, l := range f.LayersMissing {
		if !want[l] {
			t.Errorf("unexpected missing layer %q", l)
		}
	}
}

// TestOpenFlowWithGapsIsNotYetPartial: records may still be arriving. Declaring
// a gap early shows analysts a hole that does not exist.
func TestOpenFlowWithGapsIsNotYetPartial(t *testing.T) {
	events := []schema.Event{event("cf", schema.LayerEdge, base, schema.ActionAllowed)}
	f := Materialize("ray:abc", events, opts(false))
	if f.Completeness == Partial {
		t.Error("an open flow must not be reported partial before its window elapses")
	}
	if f.ClosedAt != nil {
		t.Error("an open flow has no close time")
	}
}

// TestTerminatingLayerIsTheFirstOne: once the edge blocks, later opinions are
// advisory. Crediting the last verdict blames the wrong system.
func TestTerminatingLayerIsTheFirstOne(t *testing.T) {
	events := []schema.Event{
		event("cf", schema.LayerEdge, base, schema.ActionBlocked),
		event("f5", schema.LayerAppFirewall, base.Add(2*time.Millisecond), schema.ActionLogged),
	}
	f := Materialize("ray:abc", events, opts(true))

	if f.TerminatingLayer != schema.LayerEdge {
		t.Errorf("the edge blocked first, so it terminated the request; got %q", f.TerminatingLayer)
	}
	if f.EffectiveOutcome != schema.ActionBlocked {
		t.Errorf("effective outcome: got %q", f.EffectiveOutcome)
	}
}

func TestNonTerminatedFlowReportsDeepestOutcome(t *testing.T) {
	events := []schema.Event{
		event("cf", schema.LayerEdge, base, schema.ActionAllowed),
		event("ngx", schema.LayerOrigin, base.Add(3*time.Millisecond), schema.ActionAllowed),
	}
	f := Materialize("ray:abc", events, opts(true))
	if f.TerminatingLayer != "" {
		t.Errorf("nothing terminated this request, got %q", f.TerminatingLayer)
	}
	if f.EffectiveOutcome != schema.ActionAllowed {
		t.Errorf("outcome: got %q", f.EffectiveOutcome)
	}
}

// TestMaterializationIsDeterministic underpins FR-022.
func TestMaterializationIsDeterministic(t *testing.T) {
	events := []schema.Event{
		event("ngx", schema.LayerOrigin, base.Add(3*time.Millisecond), schema.ActionAllowed),
		event("cf", schema.LayerEdge, base, schema.ActionBlocked),
		event("f5", schema.LayerAppFirewall, base.Add(2*time.Millisecond), schema.ActionLogged),
	}
	reversed := []schema.Event{events[2], events[1], events[0]}

	a := Materialize("ray:abc", events, opts(true))
	b := Materialize("ray:abc", reversed, opts(true))

	if a.FlowID != b.FlowID || a.EffectiveOutcome != b.EffectiveOutcome ||
		a.TerminatingLayer != b.TerminatingLayer || a.Completeness != b.Completeness {
		t.Fatalf("reprocessing in a different order must yield an identical flow:\n a=%+v\n b=%+v", a, b)
	}
	for i := range a.Events {
		if a.Events[i].EventID != b.Events[i].EventID {
			t.Fatalf("event order differs at %d: %s vs %s", i, a.Events[i].EventID, b.Events[i].EventID)
		}
	}
}

// TestClockSkewSurfacesOnTheFlow: an analyst reads the flow, not each event, so
// a condition buried on one event is invisible in practice.
func TestClockSkewSurfacesOnTheFlow(t *testing.T) {
	events := []schema.Event{
		event("cf", schema.LayerEdge, base, schema.ActionAllowed),
		event("ngx", schema.LayerOrigin, base.Add(-5*time.Second), schema.ActionAllowed),
	}
	f := Materialize("ray:abc", events, opts(true))
	if !f.HasFlag(schema.FlagClockSkew) {
		t.Error("a 5s backwards jump between layers must surface as a flow-level flag")
	}
}

func TestHeuristicJoinScoresLowerAndIsFlagged(t *testing.T) {
	events := []schema.Event{
		event("cf", schema.LayerEdge, base, schema.ActionAllowed),
		event("ngx", schema.LayerOrigin, base.Add(3*time.Millisecond), schema.ActionAllowed),
	}
	o := opts(true)
	o.Method = keys.TierHeuristic
	f := Materialize("ray:abc", events, o)

	if f.Confidence >= 1.0 {
		t.Errorf("a heuristic join is not certain, got confidence %v", f.Confidence)
	}
	if !f.HasFlag(schema.FlagHeuristicCorrelation) {
		t.Error("heuristic correlation must be flagged so an analyst can weigh it")
	}
}

func TestBridgedFlowIsFlagged(t *testing.T) {
	events := []schema.Event{event("cf", schema.LayerEdge, base, schema.ActionAllowed)}
	o := opts(true)
	o.Bridged = true
	f := Materialize("ray:abc", events, o)
	if !f.HasFlag(schema.FlagBridgedCorrelation) {
		t.Error("a bridged join depends on the Cloudflare custom-field capture and should be visible")
	}
}

func TestEmptyEventSetYieldsNoFlow(t *testing.T) {
	if f := Materialize("ray:abc", nil, opts(true)); f != nil {
		t.Fatal("no events means no flow")
	}
}

// TestPipelineCarriesBridgedThroughToTheFlow guards a fact that is easy to lose:
// grouping knows a component was bridged, but the correlation window does not,
// so the pipeline must carry it across. Losing it silently understates how much
// a flow depended on the Cloudflare custom-field capture being configured.
func TestPipelineCarriesBridgedThroughToTheFlow(t *testing.T) {
	store := &captureStore{}
	w := newTestWindow()
	p := NewPipeline(store, nil, w)
	p.Now = func() time.Time { return base }

	// Cloudflare record carrying BOTH identifier spaces, plus a DataDome record
	// that knows only its own id: the bridge case.
	cf := schema.Event{
		EventID: "cf-1", Tenant: "acme", Provider: schema.ProviderCloudflare,
		Layer: schema.LayerEdge, EventTime: base,
		Identifiers: []string{"ray:r1", "dd:d1"},
		Verdict:     schema.Verdict{Action: schema.ActionAllowed, Mapped: true},
	}
	dd := schema.Event{
		EventID: "dd-1", Tenant: "acme", Provider: schema.ProviderDataDome,
		Layer: schema.LayerBotManagement, EventTime: base.Add(time.Millisecond),
		Identifiers: []string{"dd:d1"},
		Verdict:     schema.Verdict{Action: schema.ActionAllowed, Mapped: true},
	}
	p.accumulate(cf, base)
	p.accumulate(dd, base)
	p.Correlate()

	// Force the window past its late-arrival bound so the flow closes.
	p.Now = func() time.Time { return base.Add(time.Hour) }
	if _, err := p.Flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}

	if len(store.flows) != 1 {
		t.Fatalf("expected one stored flow, got %d", len(store.flows))
	}
	if !store.flows[0].Bridged {
		t.Fatal("the flow was only connected because the Cloudflare record carried " +
			"both identifiers; losing that fact hides a dependency on Logpush custom fields")
	}
	if !store.flows[0].HasFlag(schema.FlagBridgedCorrelation) {
		t.Error("a bridged flow must carry the corresponding quality flag")
	}
}

type captureStore struct{ flows []*Flow }

func (c *captureStore) Store(_ context.Context, f *Flow) error {
	c.flows = append(c.flows, f)
	return nil
}
func (c *captureStore) StoreRaw(context.Context, string, schema.Provider, []RawItem, time.Time) error {
	return nil
}

func newTestWindow() *window.Window {
	return window.New(window.Options{LateArrival: time.Minute, ExpectedLayers: 4})
}

func TestTimingAttributionSumsPerLayer(t *testing.T) {
	e1 := event("cf", schema.LayerEdge, base, schema.ActionAllowed)
	e1.Response.DurationMS = 120
	e2 := event("ngx", schema.LayerOrigin, base.Add(time.Millisecond), schema.ActionAllowed)
	e2.Response.DurationMS = 40

	f := Materialize("ray:abc", []schema.Event{e1, e2}, opts(true))
	if f.TimingAttribution[schema.LayerEdge] != 120 {
		t.Errorf("edge timing: got %v", f.TimingAttribution[schema.LayerEdge])
	}
	if f.TimingAttribution[schema.LayerOrigin] != 40 {
		t.Errorf("origin timing: got %v", f.TimingAttribution[schema.LayerOrigin])
	}
}

func TestDenormalizationPrefersTheEarliestLayer(t *testing.T) {
	// The edge sees the true client before any proxy hop rewrites it, so earlier
	// layers win and later ones fill only what is still missing.
	edge := event("cf", schema.LayerEdge, base, schema.ActionAllowed)
	edge.Client.IP = "203.0.113.9"
	edge.Request.Host = "shop.example.com"

	origin := event("ngx", schema.LayerOrigin, base.Add(time.Millisecond), schema.ActionAllowed)
	origin.Client.IP = "172.16.0.5" // an edge address; must not win
	origin.Request.Path = "/cart"   // absent upstream, so it should fill in

	f := Materialize("ray:abc", []schema.Event{edge, origin}, opts(true))
	if f.Client.IP != "203.0.113.9" {
		t.Errorf("the edge's client address must win, got %q", f.Client.IP)
	}
	if f.Request.Path != "/cart" {
		t.Errorf("a later layer should fill what is missing, got %q", f.Request.Path)
	}
}

func TestSortFlowsNewestFirst(t *testing.T) {
	a := &Flow{FlowID: "a", FirstSeen: base}
	b := &Flow{FlowID: "b", FirstSeen: base.Add(time.Hour)}
	flows := []*Flow{a, b}
	SortFlows(flows)
	if flows[0].FlowID != "b" {
		t.Errorf("newest first, got %s", flows[0].FlowID)
	}
}

func TestAmbiguousMethodYieldsAmbiguousFlow(t *testing.T) {
	o := opts(true)
	o.Method = keys.TierNone
	f := Materialize("ray:abc", []schema.Event{
		event("cf", schema.LayerEdge, base, schema.ActionAllowed),
	}, o)
	if f.Completeness != Ambiguous {
		t.Errorf("an unjoined flow is ambiguous, got %q", f.Completeness)
	}
	if f.Confidence != 0 {
		t.Errorf("no confidence in an unjoined flow, got %v", f.Confidence)
	}
}

func TestDeadLetterOnParseFailure(t *testing.T) {
	dl := &ingest.MemoryDeadLetter{}
	p := NewPipeline(&captureStore{}, dl, newTestWindow())
	p.Register(failingParser{})

	err := p.ProcessBatch(context.Background(), ingest.RawBatch{
		Provider: schema.ProviderNginx, Tenant: "acme",
		Records: [][]byte{[]byte("unparseable")},
	})
	if err != nil {
		t.Fatalf("a parse failure must not fail the batch: %v", err)
	}
	if len(dl.Records) != 1 {
		t.Fatalf("the record must be dead-lettered, got %d", len(dl.Records))
	}
	if string(dl.Records[0].Payload) != "unparseable" {
		t.Error("the ORIGINAL bytes must be preserved for later reprocessing")
	}
}

type failingParser struct{}

func (failingParser) Provider() schema.Provider { return schema.ProviderNginx }
func (failingParser) Version() string           { return "test/1.0" }
func (failingParser) Parse([]byte, time.Time) (*schema.Event, error) {
	return nil, &normalize.ParseError{Provider: schema.ProviderNginx, Version: "test/1.0", Reason: "nope"}
}

// TestMaskingHappensBeforeStorage is the FR-015 guarantee at the pipeline level.
// A secret masked only on the way out is still a secret in the store.
func TestMaskingHappensBeforeStorage(t *testing.T) {
	store := &captureStore{}
	p := NewPipeline(store, nil, newTestWindow())
	p.Now = func() time.Time { return base }
	p.Masker = normalize.NewMasker([]byte("key"))
	p.Register(headerParser{})

	if err := p.ProcessBatch(context.Background(), ingest.RawBatch{
		Provider: schema.ProviderNginx, Tenant: "acme",
		Records: [][]byte{[]byte("record")},
	}); err != nil {
		t.Fatalf("process: %v", err)
	}
	p.Correlate()
	p.Now = func() time.Time { return base.Add(time.Hour) }
	if _, err := p.Flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}

	if len(store.flows) != 1 {
		t.Fatalf("expected one stored flow, got %d", len(store.flows))
	}
	stored := store.flows[0].Events[0]
	if got := stored.Request.Headers["Authorization"]; got != "[redacted]" {
		t.Fatalf("the credential reached storage unmasked: %q", got)
	}
	if !stored.HasFlag(schema.FlagFieldsMasked) {
		t.Error("the stored event must record that it was masked")
	}
}

type headerParser struct{}

func (headerParser) Provider() schema.Provider { return schema.ProviderNginx }
func (headerParser) Version() string           { return "test/1.0" }
func (headerParser) Parse(_ []byte, at time.Time) (*schema.Event, error) {
	return &schema.Event{
		EventID: "e1", Provider: schema.ProviderNginx, Layer: schema.LayerOrigin,
		EventTime: base, ReceivedAt: at,
		Identifiers: []string{"ray:abc"},
		Request: schema.Request{Headers: map[string]string{
			"Authorization": "Bearer supersecrettoken1234567890",
			"User-Agent":    "curl/8.0",
		}},
		Verdict: schema.Verdict{Action: schema.ActionAllowed, Mapped: true},
	}, nil
}

// TestPipelineSurvivesConcurrentIngestAndFlush reproduces the crash the burst
// test found: ProcessBatch on the consumer goroutine racing Correlate/Flush on
// the ticker goroutine died with "concurrent map read and map write" at
// production rates.
func TestPipelineSurvivesConcurrentIngestAndFlush(t *testing.T) {
	p := NewPipeline(&captureStore{}, nil, newTestWindow())
	p.Register(headerParser{})
	p.Now = func() time.Time { return base }

	done := make(chan struct{})
	go func() {
		for i := 0; i < 300; i++ {
			_ = p.ProcessBatch(context.Background(), ingest.RawBatch{
				BatchID: "b", Provider: schema.ProviderNginx, Tenant: "acme",
				Records: [][]byte{[]byte("r")},
			})
		}
		done <- struct{}{}
	}()
	go func() {
		for i := 0; i < 300; i++ {
			p.Correlate()
			_, _ = p.Flush(context.Background())
		}
		done <- struct{}{}
	}()
	<-done
	<-done
}
