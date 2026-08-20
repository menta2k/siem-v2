package victorialogs

import (
	"strings"
	"testing"
	"time"
)

func TestQueryIsAlwaysTenantScoped(t *testing.T) {
	// Even an entirely empty search must produce a tenant-scoped query. Scoping
	// is not conditional on the caller asking for it.
	q, err := BuildFlowQuery("acme", FlowSearch{})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if !strings.Contains(q, `tenant="acme"`) {
		t.Fatalf("query is not tenant-scoped: %s", q)
	}
	if !strings.Contains(q, `record_kind="flow"`) {
		t.Errorf("query should be scoped to flow documents: %s", q)
	}
}

// TestInjectionAttemptsAreRejected is the FR-074b guarantee in practice: a
// caller cannot escape their tenant because there is no syntax in which to try.
func TestInjectionAttemptsAreRejected(t *testing.T) {
	attempts := []string{
		`acme"} or {tenant="globex`,
		`" or tenant:="globex`,
		`x | drop_fields _msg`,
		`x} {tenant="globex"`,
		"x\nquery=*",
		`*`,
		`x' OR '1'='1`,
	}
	for _, attempt := range attempts {
		t.Run(attempt, func(t *testing.T) {
			q, err := BuildFlowQuery("acme", FlowSearch{ClientIP: attempt})
			if err == nil {
				// If it did not error, it must at minimum not have escaped the tenant.
				if strings.Contains(q, "globex") || strings.Count(q, "tenant=") != 1 {
					t.Fatalf("injection succeeded: %s", q)
				}
				t.Fatalf("unsafe value was accepted rather than rejected: %s", q)
			}
			var unsafe *ErrUnsafeValue
			if !asUnsafe(err, &unsafe) {
				t.Fatalf("expected ErrUnsafeValue, got %T: %v", err, err)
			}
		})
	}
}

// TestErrorDoesNotEchoTheAttempt: reflecting the payload back would help an
// attacker refine it and could carry it into a log or UI unescaped.
func TestErrorDoesNotEchoTheAttempt(t *testing.T) {
	payload := `x"} or {tenant="globex`
	_, err := BuildFlowQuery("acme", FlowSearch{ClientIP: payload})
	if err == nil {
		t.Fatal("expected rejection")
	}
	if strings.Contains(err.Error(), "globex") {
		t.Errorf("the error message echoes the injection payload: %v", err)
	}
}

func TestTypedFiltersCompile(t *testing.T) {
	from := time.Date(2026, 8, 19, 0, 0, 0, 0, time.UTC)
	q, err := BuildFlowQuery("acme", FlowSearch{
		From: from, To: from.Add(time.Hour),
		ClientIP: "203.0.113.9", Host: "shop.example.com",
		Method: "post", Status: 403, Action: "blocked",
		PathPrefix: "/admin", Country: "de",
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	for _, want := range []string{
		`client_ip:="203.0.113.9"`, `host:="shop.example.com"`,
		`method:="POST"`, `status:=403`, `effective_outcome:="blocked"`,
		`country:="DE"`, `_time:[`,
	} {
		if !strings.Contains(q, want) {
			t.Errorf("query missing %q: %s", want, q)
		}
	}
}

func TestEmptyTenantRejected(t *testing.T) {
	if _, err := BuildFlowQuery("", FlowSearch{}); err == nil {
		t.Fatal("an empty tenant must be refused; it would produce an unscoped query")
	}
}

func TestFlowByIDIsScoped(t *testing.T) {
	q, err := BuildFlowByIDQuery("acme", "flow:ray:abc")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if !strings.Contains(q, `tenant="acme"`) || !strings.Contains(q, `flow_id:="flow:ray:abc"`) {
		t.Fatalf("unexpected query: %s", q)
	}
	if _, err := BuildFlowByIDQuery("acme", `x" or flow_id:="y`); err == nil {
		t.Fatal("an injected flow id must be rejected")
	}
}

// TestStreamFieldsStayLowCardinality guards the storage rule that a future
// change is most likely to break.
func TestStreamFieldsStayLowCardinality(t *testing.T) {
	forbidden := map[string]bool{
		"correlation_key": true, "ray_id": true, "client_ip": true,
		"flow_id": true, "event_id": true, "user_agent": true, "vendor_request_id": true,
	}
	for _, f := range streamFields {
		if forbidden[f] {
			t.Fatalf("%q is high-cardinality and must never be a stream field: "+
				"the VictoriaLogs docs are explicit that trace_id and ip must not be "+
				"stream fields, and doing so degrades the whole store", f)
		}
	}
}

func asUnsafe(err error, target **ErrUnsafeValue) bool {
	u, ok := err.(*ErrUnsafeValue)
	if ok {
		*target = u
	}
	return ok
}

func TestEnrichedFiltersCompile(t *testing.T) {
	yes := true
	q, err := BuildFlowQuery("acme", FlowSearch{
		RayID: "a2d6ea0f6813ccd4", CorrelationMethod: "heuristic",
		Bridged: &yes, ASN: 64512, MinLayers: 2, MaxLayers: 4,
		HasQualityFlag: "clock_skew",
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	for _, want := range []string{
		`ray_id:="a2d6ea0f6813ccd4"`, `correlation_method:="heuristic"`,
		"bridged:=true", "asn:=64512", "layer_count:>=2", "layer_count:<=4",
		`data_quality_flags:"clock_skew"`,
	} {
		if !strings.Contains(q, want) {
			t.Errorf("query missing %q: %s", want, q)
		}
	}
}

func TestEnrichedFiltersRejectInjection(t *testing.T) {
	for name, s := range map[string]FlowSearch{
		"ray id":       {RayID: `x" or tenant:="globex`},
		"method":       {CorrelationMethod: `x"} {`},
		"quality flag": {HasQualityFlag: `x" or *`},
	} {
		if _, err := BuildFlowQuery("acme", s); err == nil {
			t.Errorf("%s: an injected value must be rejected", name)
		}
	}
}

// TestProviderFiltersOnParticipation: the flow record's own "provider" field
// is the literal "correlated" (it distinguishes nothing — record_kind does
// that), so filtering must match the PARTICIPATING providers word-list. The
// bug this pins: provider:=nginx against provider="correlated" matched
// nothing, ever.
func TestProviderFiltersOnParticipation(t *testing.T) {
	q, err := BuildFlowQuery("acme", FlowSearch{Provider: "f5asm", Limit: 10})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if !strings.Contains(q, `providers:"f5asm"`) {
		t.Fatalf("provider must word-match the providers list, got: %s", q)
	}
	if strings.Contains(q, `provider:=`) {
		t.Fatalf("exact match on the flow record's constant provider field can never match: %s", q)
	}
}

// TestPaginationIsDeterministic: pages only mean anything when the server
// orders results before slicing them. Without an explicit sort, VictoriaLogs
// returns an arbitrary subset and consecutive pages can overlap or skip.
func TestPaginationIsDeterministic(t *testing.T) {
	q, err := BuildFlowQuery("acme", FlowSearch{Limit: 50, Offset: 100})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	for _, want := range []string{"| sort by (_time desc)", "| offset 100", "| limit 50"} {
		if !strings.Contains(q, want) {
			t.Fatalf("query must carry %q for stable pages, got: %s", want, q)
		}
	}
	// The sort must come BEFORE offset/limit or the slice is of unsorted rows.
	if strings.Index(q, "sort by") > strings.Index(q, "offset") {
		t.Fatalf("sort must precede offset: %s", q)
	}
}

func TestLimitIsBoundedAndDefaulted(t *testing.T) {
	q, _ := BuildFlowQuery("acme", FlowSearch{})
	if !strings.Contains(q, "| limit 50") {
		t.Fatalf("default page size must be 50: %s", q)
	}
	q, _ = BuildFlowQuery("acme", FlowSearch{Limit: 100000})
	if !strings.Contains(q, "| limit 1000") {
		t.Fatalf("page size must be capped at 1000: %s", q)
	}
	if _, err := BuildFlowQuery("acme", FlowSearch{Offset: -1}); err == nil {
		t.Fatal("negative offset must be refused")
	}
}
