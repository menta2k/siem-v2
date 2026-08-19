//go:build scenario

// Package scenarios runs recorded end-to-end replays through the full pipeline.
package scenarios

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/menta2k/siem-v2/backend/internal/biz/flow"
	"github.com/menta2k/siem-v2/backend/internal/correlate/group"
	"github.com/menta2k/siem-v2/backend/internal/correlate/keys"
	"github.com/menta2k/siem-v2/backend/internal/normalize"
	"github.com/menta2k/siem-v2/backend/internal/normalize/cloudflare"
	"github.com/menta2k/siem-v2/backend/internal/normalize/datadome"
	"github.com/menta2k/siem-v2/backend/internal/normalize/f5asm"
	"github.com/menta2k/siem-v2/backend/internal/normalize/nginx"
	"github.com/menta2k/siem-v2/backend/internal/normalize/schema"
)

var receivedAt = time.Date(2026, 8, 19, 12, 0, 10, 0, time.UTC)

// TestOutOfOrderReconstruction is the S1 scenario from quickstart.md and the
// acceptance test for User Story 1.
//
// Records from all four providers are fed in DELIBERATELY WRONG ORDER — origin
// first, edge last — which is what actually happens in production because the
// providers deliver on independent schedules. The reconstructed flow must still
// place the layers in true causal order.
func TestOutOfOrderReconstruction(t *testing.T) {
	events := loadAllProviders(t)

	// Deliver in the worst plausible order: origin, WAF, bot, edge.
	shuffled := reorder(events, []schema.Provider{
		schema.ProviderNginx, schema.ProviderF5ASM,
		schema.ProviderDataDome, schema.ProviderCloudflare,
	})

	records := make([]group.Record, 0, len(shuffled))
	byID := map[string]schema.Event{}
	for _, e := range shuffled {
		ids := make([]keys.Identifier, 0, len(e.Identifiers))
		for _, s := range e.Identifiers {
			ids = append(ids, parseID(s))
		}
		records = append(records, group.Record{
			EventID: e.EventID, Provider: string(e.Provider), Identifiers: ids,
		})
		byID[e.EventID] = e
	}

	components := group.Exact(records)
	if len(components) == 0 {
		t.Fatal("no components formed; correlation produced nothing")
	}

	// Expected outcome per request. Both the blocked SQLi and the allowed /cart
	// request span all four providers, so asserting a single outcome for "any
	// four-provider flow" would be wrong — the allowed one is not a failure.
	wantOutcome := map[string]schema.Action{
		"dd:dd-req-99":  schema.ActionBlocked, // SQLi, blocked at the edge
		"dd:dd-req-100": schema.ActionAllowed, // ordinary POST /cart
	}

	seen := map[string]bool{}
	for _, c := range components {
		members := make([]schema.Event, 0, len(c.EventIDs))
		for _, id := range c.EventIDs {
			members = append(members, byID[id])
		}
		f := flow.Materialize(c.Key.Value, members, flow.Options{
			Tenant: "acme", Method: c.Key.Tier, Bridged: c.Bridged,
			Closed: true, Now: receivedAt,
		})

		want, tracked := wantOutcome[c.Key.Value]
		if !tracked {
			continue
		}
		seen[c.Key.Value] = true

		if len(c.Providers) != 4 {
			t.Errorf("%s: expected all four providers, got %v", c.Key.Value, c.Providers)
		}
		assertCausalOrder(t, f)
		if f.Completeness != flow.Complete {
			t.Errorf("%s: should be complete, got %q missing=%v", c.Key.Value, f.Completeness, f.LayersMissing)
		}
		if f.EffectiveOutcome != want {
			t.Errorf("%s: effective outcome = %q, want %q", c.Key.Value, f.EffectiveOutcome, want)
		}
		if !f.Bridged {
			t.Errorf("%s: DataDome joined through the Cloudflare record, so this is a bridged flow", c.Key.Value)
		}
		if f.Method != keys.TierExact {
			t.Errorf("%s: shared-identifier joins must be exact, got %q", c.Key.Value, f.Method)
		}
	}

	for key := range wantOutcome {
		if !seen[key] {
			t.Errorf("no flow formed for %s; the DataDome<->Cloudflare bridge is not working", key)
		}
	}
}

// assertCausalOrder is the heart of the scenario: layer order must follow the
// request path regardless of delivery order or provider clocks.
func assertCausalOrder(t *testing.T, f *flow.Flow) {
	t.Helper()
	want := []schema.Layer{
		schema.LayerEdge, schema.LayerBotManagement,
		schema.LayerAppFirewall, schema.LayerOrigin,
	}
	if len(f.Events) != len(want) {
		t.Fatalf("expected %d events, got %d", len(want), len(f.Events))
	}
	for i, layer := range want {
		if f.Events[i].Layer != layer {
			t.Fatalf("position %d: want layer %q, got %q (order: %v)",
				i, layer, f.Events[i].Layer, layersOf(f))
		}
	}
}

func loadAllProviders(t *testing.T) []schema.Event {
	t.Helper()
	var events []schema.Event

	cfP := cloudflare.New()
	for _, line := range readLines(t, "../fixtures/cloudflare/http_requests_modern.ndjson") {
		events = append(events, mustParse(t, cfP, []byte(line)))
	}

	ddP := datadome.New()
	raw, err := os.ReadFile("../fixtures/datadome/logs_export.json")
	if err != nil {
		t.Fatalf("read datadome fixture: %v", err)
	}
	var ddRecords []json.RawMessage
	if err := json.Unmarshal(raw, &ddRecords); err != nil {
		t.Fatalf("decode datadome fixture: %v", err)
	}
	for _, r := range ddRecords {
		events = append(events, mustParse(t, ddP, r))
	}

	f5P := f5asm.New()
	for _, line := range readLines(t, "../fixtures/f5asm/asm_kv.log") {
		events = append(events, mustParse(t, f5P, []byte(line)))
	}

	ngxP := nginx.New()
	for _, line := range readLines(t, "../fixtures/nginx/access.ndjson") {
		events = append(events, mustParse(t, ngxP, []byte(line)))
	}
	return events
}

func mustParse(t *testing.T, p normalize.Parser, raw []byte) schema.Event {
	t.Helper()
	e, err := p.Parse(raw, receivedAt)
	if err != nil {
		t.Fatalf("%s parser: %v", p.Provider(), err)
	}
	return *e
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" {
			out = append(out, l)
		}
	}
	return out
}

func reorder(events []schema.Event, order []schema.Provider) []schema.Event {
	out := make([]schema.Event, 0, len(events))
	for _, p := range order {
		for _, e := range events {
			if e.Provider == p {
				out = append(out, e)
			}
		}
	}
	return out
}

func parseID(s string) keys.Identifier {
	if i := strings.IndexByte(s, ':'); i >= 0 {
		return keys.Identifier{Namespace: s[:i], Value: s[i+1:]}
	}
	return keys.Identifier{Value: s}
}

func layersOf(f *flow.Flow) []schema.Layer {
	out := make([]schema.Layer, 0, len(f.Events))
	for _, e := range f.Events {
		out = append(out, e.Layer)
	}
	return out
}
