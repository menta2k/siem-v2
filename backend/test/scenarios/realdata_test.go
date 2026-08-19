//go:build realdata

package scenarios

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/menta2k/siem-v2/backend/internal/biz/flow"
	"github.com/menta2k/siem-v2/backend/internal/correlate/group"
	"github.com/menta2k/siem-v2/backend/internal/correlate/keys"
	"github.com/menta2k/siem-v2/backend/internal/normalize/cloudflare"
	"github.com/menta2k/siem-v2/backend/internal/normalize/f5asm"
	"github.com/menta2k/siem-v2/backend/internal/normalize/nginx"
	"github.com/menta2k/siem-v2/backend/internal/normalize/schema"
)

// TestRealProviderRecords parses the operator's real captures.
//
// The captures are gitignored and nothing from them is copied into fixtures;
// this only asserts that the parsers handle the shapes providers ACTUALLY emit,
// which is a different question from handling the shapes we imagined.
func TestRealProviderRecords(t *testing.T) {
	root := os.Getenv("SIEM_RAW_DIR")
	if root == "" {
		root = "../../../raw"
	}
	at := time.Now().UTC()

	t.Run("cloudflare", func(t *testing.T) {
		raw := firstLine(t, filepath.Join(root, "cf.raw"))
		e, err := cloudflare.New().Parse(raw, at)
		if err != nil {
			t.Fatalf("real Cloudflare record failed to parse: %v", err)
		}
		if e.RayID == "" {
			t.Error("no ray id extracted")
		}
		if e.EventTime.IsZero() {
			t.Error("no event time extracted")
		}
		t.Logf("edge: ray=%s action=%s mapped=%v ids=%d", e.RayID, e.Verdict.Action, e.Verdict.Mapped, len(e.Identifiers))
	})

	t.Run("datadome_worker_subrequest", func(t *testing.T) {
		raw := firstLine(t, filepath.Join(root, "dd.raw"))
		e, err := cloudflare.New().Parse(raw, at)
		if err != nil {
			t.Fatalf("real DataDome subrequest failed to parse: %v", err)
		}

		// A Worker subrequest must become the BOT layer, not an edge event: it is
		// a POST to DataDome's API, not a visitor request.
		if e.Provider != schema.ProviderDataDome {
			t.Fatalf("a DataDome subrequest must yield the bot layer, got provider %q", e.Provider)
		}
		if e.Layer != schema.LayerBotManagement {
			t.Errorf("layer should be bot_management, got %q", e.Layer)
		}
		// It must be keyed on the PARENT ray, so it joins the original request.
		if e.RayID == "" {
			t.Fatal("no parent ray; the verdict cannot be attached to any request")
		}
		if e.RayID == e.VendorRequestID {
			t.Error("the event must key on the parent ray, not the subrequest's own ray")
		}
		t.Logf("bot layer: parent_ray=%s subrequest_ray=%s action=%s mapped=%v",
			e.RayID, e.VendorRequestID, e.Verdict.Action, e.Verdict.Mapped)
	})

	t.Run("nginx", func(t *testing.T) {
		raw := firstLine(t, filepath.Join(root, "nginx.raw"))
		e, err := nginx.New().Parse(raw, at)
		if err != nil {
			t.Fatalf("real nginx record failed to parse: %v", err)
		}
		if e.RayID == "" {
			t.Fatal("no ray id from cf_ray; the origin layer cannot join exactly")
		}
		// The wire value carries a datacentre suffix; Cloudflare logs the bare id.
		if len(e.RayID) != 16 {
			t.Errorf("ray id %q is not the 16-char form Cloudflare logs; the join will miss", e.RayID)
		}
		if e.Client.IP == "" {
			t.Error("no client ip resolved")
		}
		t.Logf("origin: ray=%s status=%d client=%s", e.RayID, e.Response.Status, maskIP(e.Client.IP))
	})

	t.Run("f5asm", func(t *testing.T) {
		raw := firstLine(t, filepath.Join(root, "f5.raw"))
		e, err := f5asm.New().Parse(raw, at)
		if err != nil {
			t.Fatalf("real F5 record failed to parse: %v", err)
		}
		t.Logf("waf: action=%s mapped=%v rule=%q ray=%q",
			e.Verdict.Action, e.Verdict.Mapped, e.Verdict.RuleID, e.RayID)
		if e.RayID == "" {
			t.Log("NOTE: no CF-Ray in the F5 record — this is verification item V2. " +
				"The F5 layer will join heuristically until the iRule is in place.")
		}
	})
}

func firstLine(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("real capture not available: %v", err)
	}
	for _, line := range splitLines(data) {
		if len(line) > 0 {
			return line
		}
	}
	t.Fatalf("%s is empty", path)
	return nil
}

func splitLines(data []byte) [][]byte {
	var out [][]byte
	start := 0
	for i, b := range data {
		if b == '\n' {
			out = append(out, trim(data[start:i]))
			start = i + 1
		}
	}
	out = append(out, trim(data[start:]))
	return out
}

func trim(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\r' || b[len(b)-1] == ' ') {
		b = b[:len(b)-1]
	}
	return b
}

// maskIP keeps real addresses out of test output.
func maskIP(ip string) string {
	for i := len(ip) - 1; i >= 0; i-- {
		if ip[i] == '.' || ip[i] == ':' {
			return ip[:i+1] + "x"
		}
	}
	return "x"
}

// TestRealFourLayerFlow is the end-to-end proof on the operator's own data.
//
// It asserts the join chain that a Worker deployment actually produces:
// nginx and F5 carry the Worker fetch's own ray, the DataDome subrequest is keyed
// on the visitor's parent ray, and the Cloudflare record carries both — so all
// four land in ONE flow at exact tier, with no time window and no heuristic.
func TestRealFourLayerFlow(t *testing.T) {
	root := os.Getenv("SIEM_RAW_DIR")
	if root == "" {
		root = "../../../raw"
	}
	at := time.Now().UTC()

	var events []schema.Event
	add := func(e *schema.Event, err error, what string) {
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		events = append(events, *e)
	}

	cfEvent, err := cloudflare.New().Parse(firstLine(t, filepath.Join(root, "cf.raw")), at)
	add(cfEvent, err, "cloudflare")
	ddEvent, err := cloudflare.New().Parse(firstLine(t, filepath.Join(root, "dd.raw")), at)
	add(ddEvent, err, "datadome subrequest")
	f5Event, err := f5asm.New().Parse(firstLine(t, filepath.Join(root, "f5.raw")), at)
	add(f5Event, err, "f5")
	ngEvent, err := nginx.New().Parse(firstLine(t, filepath.Join(root, "nginx.raw")), at)
	add(ngEvent, err, "nginx")

	records := make([]group.Record, 0, len(events))
	byID := map[string]schema.Event{}
	for _, e := range events {
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
	if len(components) != 1 {
		for _, c := range components {
			t.Logf("component %s: providers=%v events=%v", c.Key.Value, c.Providers, c.EventIDs)
		}
		t.Fatalf("all four real records belong to ONE request and must form ONE flow, got %d", len(components))
	}

	c := components[0]
	if len(c.Providers) != 4 {
		t.Fatalf("expected all four providers in the flow, got %v", c.Providers)
	}
	if c.Key.Tier != keys.TierExact {
		t.Errorf("this join uses shared ray ids and must be exact, got %q", c.Key.Tier)
	}
	if !c.Bridged {
		t.Error("the join depends on the Cloudflare record carrying both its own ray " +
			"and its parent ray, so the flow is bridged")
	}

	members := make([]schema.Event, 0, len(c.EventIDs))
	for _, id := range c.EventIDs {
		members = append(members, byID[id])
	}
	f := flow.Materialize(c.Key.Value, members, flow.Options{
		Tenant: "acme", Method: c.Key.Tier, Bridged: c.Bridged, Closed: true, Now: at,
	})

	if f.Completeness != flow.Complete {
		t.Errorf("all four layers reported, so the flow is complete; got %q missing=%v",
			f.Completeness, f.LayersMissing)
	}
	t.Logf("REAL FLOW: providers=%v outcome=%s terminating=%q layers=%d bridged=%v",
		c.Providers, f.EffectiveOutcome, f.TerminatingLayer, len(f.LayersPresent), f.Bridged)
	for _, e := range f.Events {
		t.Logf("  %-14s %-11s %-10s ray=%s", e.Layer, e.Provider, e.Verdict.Action, e.RayID)
	}
}
