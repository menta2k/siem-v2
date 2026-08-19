package group

import (
	"reflect"
	"testing"

	"github.com/menta2k/siem-v2/backend/internal/correlate/keys"
)

func id(t *testing.T, ns, v string) keys.Identifier {
	t.Helper()
	i, ok := keys.NewIdentifier(ns, v)
	if !ok {
		t.Fatalf("identifier %s:%s should be valid", ns, v)
	}
	return i
}

// TestDataDomeJoinsNginxTransitively is the core case from research.md R11a.
//
// A DataDome record knows only its own requestid. An nginx line knows only the
// ray id. They share nothing. The Cloudflare record carries BOTH, so all three
// must land in one component at exact tier.
func TestDataDomeJoinsNginxTransitively(t *testing.T) {
	records := []Record{
		{
			EventID:  "cf-1",
			Provider: "cloudflare",
			// The bridging record: two identifier spaces in one record.
			Identifiers: []keys.Identifier{
				id(t, keys.NSRayID, "8f2a3b4c"),
				id(t, keys.NSDataDome, "dd-req-99"),
			},
		},
		{
			EventID:     "dd-1",
			Provider:    "datadome",
			Identifiers: []keys.Identifier{id(t, keys.NSDataDome, "dd-req-99")},
		},
		{
			EventID:     "ngx-1",
			Provider:    "nginx",
			Identifiers: []keys.Identifier{id(t, keys.NSRayID, "8f2a3b4c")},
		},
	}

	components := Exact(records)
	if len(components) != 1 {
		t.Fatalf("expected all three records in ONE component, got %d: %+v", len(components), components)
	}
	c := components[0]
	want := []string{"cf-1", "dd-1", "ngx-1"}
	if !reflect.DeepEqual(c.EventIDs, want) {
		t.Fatalf("expected %v, got %v", want, c.EventIDs)
	}
	if c.Key.Tier != keys.TierExact {
		t.Fatalf("transitive join must be exact tier, not %q — it does not depend on clocks", c.Key.Tier)
	}
	if !c.Bridged {
		t.Fatal("component must be marked bridged: the join depended on the Cloudflare " +
			"custom-field capture carrying both identifiers")
	}
}

// TestWithoutBridgeRecordTheyDoNotJoin is the negative case that gives the
// positive one meaning. Remove the Cloudflare record and DataDome and nginx must
// NOT be joined — anything else would mean we are inventing joins.
func TestWithoutBridgeRecordTheyDoNotJoin(t *testing.T) {
	records := []Record{
		{EventID: "dd-1", Provider: "datadome", Identifiers: []keys.Identifier{id(t, keys.NSDataDome, "dd-req-99")}},
		{EventID: "ngx-1", Provider: "nginx", Identifiers: []keys.Identifier{id(t, keys.NSRayID, "8f2a3b4c")}},
	}
	components := Exact(records)
	if len(components) != 2 {
		t.Fatalf("without the bridging record these must stay separate; got %d components", len(components))
	}
}

func TestGroupingIsOrderIndependent(t *testing.T) {
	base := []Record{
		{EventID: "cf-1", Provider: "cloudflare", Identifiers: []keys.Identifier{
			id(t, keys.NSRayID, "ray-a"), id(t, keys.NSDataDome, "dd-a")}},
		{EventID: "dd-1", Provider: "datadome", Identifiers: []keys.Identifier{id(t, keys.NSDataDome, "dd-a")}},
		{EventID: "ngx-1", Provider: "nginx", Identifiers: []keys.Identifier{id(t, keys.NSRayID, "ray-a")}},
		{EventID: "f5-1", Provider: "f5asm", Identifiers: []keys.Identifier{id(t, keys.NSRayID, "ray-a")}},
	}
	reversed := make([]Record, len(base))
	for i, r := range base {
		reversed[len(base)-1-i] = r
	}

	a, b := Exact(base), Exact(reversed)
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("reprocessing in a different order must yield identical components (FR-022)\n got: %+v\nwant: %+v", b, a)
	}
	if len(a) != 1 || len(a[0].EventIDs) != 4 {
		t.Fatalf("expected one component of four records, got %+v", a)
	}
}

func TestSeparateRequestsStaySeparate(t *testing.T) {
	records := []Record{
		{EventID: "cf-1", Provider: "cloudflare", Identifiers: []keys.Identifier{id(t, keys.NSRayID, "ray-1")}},
		{EventID: "ngx-1", Provider: "nginx", Identifiers: []keys.Identifier{id(t, keys.NSRayID, "ray-1")}},
		{EventID: "cf-2", Provider: "cloudflare", Identifiers: []keys.Identifier{id(t, keys.NSRayID, "ray-2")}},
		{EventID: "ngx-2", Provider: "nginx", Identifiers: []keys.Identifier{id(t, keys.NSRayID, "ray-2")}},
	}
	components := Exact(records)
	if len(components) != 2 {
		t.Fatalf("two distinct requests must yield two components, got %d", len(components))
	}
	for _, c := range components {
		if len(c.EventIDs) != 2 {
			t.Fatalf("each component should hold two records, got %v", c.EventIDs)
		}
		if c.Bridged {
			t.Error("a single-identifier join is not a bridge and must not be marked as one")
		}
	}
}

func TestRecordsWithoutIdentifiersFallThrough(t *testing.T) {
	records := []Record{
		{EventID: "cf-1", Provider: "cloudflare", Identifiers: []keys.Identifier{id(t, keys.NSRayID, "ray-1")}},
		{EventID: "ngx-orphan", Provider: "nginx"}, // no CF-Ray logged
	}
	components := Exact(records)
	if len(components) != 1 {
		t.Fatalf("expected one exact component, got %d", len(components))
	}
	for _, e := range components[0].EventIDs {
		if e == "ngx-orphan" {
			t.Fatal("a record with no identifier must not be attached to an exact component; " +
				"it belongs to the heuristic tier")
		}
	}
}
