package profile

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestInferTable(t *testing.T) {
	cases := map[string]ValueType{
		"":                                     TypeEmpty,
		"true":                                 TypeBool,
		"False":                                TypeBool,
		"8584286":                              TypeInt,
		"-42":                                  TypeInt,
		"3.14":                                 TypeFloat,
		"550e8400-e29b-41d4-a716-446655440000": TypeUUID,
		"192.0.2.10":                           TypeIPv4,
		"2001:db8::1":                          TypeIPv6,
		"user@example.com":                     TypeEmail,
		"2026-08-21":                           TypeDate,
		"deadbeefcafe":                         TypeHex,
		`{"a":1}`:                              TypeJSON,
		"search":                               TypeAlnum,
		"hello world":                          TypeFreetext,
	}
	for v, want := range cases {
		if got := Infer(v); got != want {
			t.Errorf("Infer(%q) = %s, want %s", v, got, want)
		}
	}
}

// TestJoinIsASemilattice: commutativity and associativity over every triple.
// The lattice is the contract that makes profile merging order-independent.
func TestJoinIsASemilattice(t *testing.T) {
	all := []ValueType{
		TypeEmpty, TypeBool, TypeInt, TypeFloat, TypeUUID, TypeIPv4, TypeIPv6,
		TypeEmail, TypeDate, TypeHex, TypeJSON, TypeAlnum, TypeFreetext,
	}
	for _, a := range all {
		if got := Join(a, a); got != a {
			t.Errorf("Join(%s,%s) = %s, want idempotent", a, a, got)
		}
		for _, b := range all {
			if Join(a, b) != Join(b, a) {
				t.Errorf("Join(%s,%s) != Join(%s,%s)", a, b, b, a)
			}
			for _, c := range all {
				left := Join(Join(a, b), c)
				right := Join(a, Join(b, c))
				if left != right {
					t.Errorf("associativity broken: (%s⊔%s)⊔%s = %s but %s⊔(%s⊔%s) = %s",
						a, b, c, left, a, b, c, right)
				}
			}
		}
	}
}

func testOptions() TemplateOptions {
	// Small thresholds so tests need few observations. Ratios mirror defaults.
	return TemplateOptions{MinSamples: 10, MaxDistinct: 8, MinDistinctForType: 4, TypeShare: 0.9, VarSingletonShare: 0.8, VarRepeatFactor: 4}
}

func TestNumericIDsCollapseToIntTemplate(t *testing.T) {
	e := NewEngine(testOptions())
	var last []string
	for i := 0; i < 20; i++ {
		last, _ = e.Normalize(fmt.Sprintf("/job/%d", 8584280+i))
	}
	if got := JoinTemplate(last); got != "/job/{int}" {
		t.Fatalf("template = %q, want /job/{int}", got)
	}
	// Once collapsed, the first ID normalizes the same way — monotonic.
	segs, _ := e.Normalize("/job/8584280")
	if got := JoinTemplate(segs); got != "/job/{int}" {
		t.Fatalf("after collapse, /job/8584280 = %q, want /job/{int}", got)
	}
}

func TestLiteralSiblingSurvivesTypedCollapse(t *testing.T) {
	e := NewEngine(testOptions())
	for i := 0; i < 20; i++ {
		e.Normalize(fmt.Sprintf("/job/%d", 8584280+i))
	}
	segs, _ := e.Normalize("/job/search")
	if got := JoinTemplate(segs); got != "/job/search" {
		t.Fatalf("literal sibling = %q, want /job/search", got)
	}
}

// TestLiteralTriggeringCollapseStaysLiteral: the observation that TIPS a
// position into a typed collapse can itself be a literal (nine distinct ints,
// then "search" arrives as the qualifying sample). The collapse must happen
// AND the literal must keep its own route.
func TestLiteralTriggeringCollapseStaysLiteral(t *testing.T) {
	e := NewEngine(testOptions())
	for i := 0; i < 9; i++ {
		e.Normalize(fmt.Sprintf("/job/%d", 8584280+i))
	}
	segs, collapsed := e.Normalize("/job/search")
	if !collapsed {
		t.Fatal("the tenth distinct sample should have tripped the typed collapse")
	}
	if got := JoinTemplate(segs); got != "/job/search" {
		t.Fatalf("triggering literal = %q, want /job/search (not swallowed by {int})", got)
	}
	segs, _ = e.Normalize("/job/8584290")
	if got := JoinTemplate(segs); got != "/job/{int}" {
		t.Fatalf("ints after collapse = %q, want /job/{int}", got)
	}
}

func TestHighCardinalityMixedValuesCollapseToVar(t *testing.T) {
	e := NewEngine(testOptions())
	var last []string
	// Unique, non-repeating values past the evidence gate: an id/token stream.
	for i := 0; i < 50; i++ {
		// Mixed shapes so no single promotable type dominates.
		last, _ = e.Normalize(fmt.Sprintf("/files/report-%d.pdf", i))
	}
	if got := JoinTemplate(last); got != "/files/{var}" {
		t.Fatalf("template = %q, want /files/{var}", got)
	}
}

func TestRepeatingRouteVocabularyStaysLiteral(t *testing.T) {
	// A site's real top-level routes: many distinct literals, each hit many
	// times. High cardinality alone must NOT fold them into /{var} — repetition
	// marks them as routes, not identifiers. (This is the jobs.bg first-segment
	// case: /front_job_search.php, /company, /candidates, ... stay distinct.)
	e := NewEngine(testOptions())
	routes := []string{
		"front_job_search.php", "company", "candidates", "back.php",
		"search_history.php", "reload.php", "suggest.php", "chat",
		"js_cv.php", "notification_counter.php", "search_form.php", "al_handshake.php",
	}
	var got map[string]bool = map[string]bool{}
	for r := 0; r < 30; r++ {
		for _, name := range routes {
			segs, _ := e.Normalize("/" + name)
			got[JoinTemplate(segs)] = true
		}
	}
	if got["/{var}"] {
		t.Fatalf("repeating route vocabulary collapsed to /{var}; templates seen: %v", keysOf(got))
	}
	for _, name := range routes {
		if !got["/"+name] {
			t.Fatalf("route /%s did not stay literal; templates seen: %v", name, keysOf(got))
		}
	}
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestSingleLiteralNeverCollapses(t *testing.T) {
	e := NewEngine(testOptions())
	var last []string
	for i := 0; i < 100; i++ {
		// /2024/report repeats one all-int value; MinDistinctForType must hold
		// the position literal.
		last, _ = e.Normalize("/2024/report")
	}
	if got := JoinTemplate(last); got != "/2024/report" {
		t.Fatalf("template = %q, want literal /2024/report", got)
	}
}

func TestLearnTemplateSurvivesRestart(t *testing.T) {
	e := NewEngine(testOptions())
	e.LearnTemplate("/api/users/{uuid}/orders/{int}")
	segs, _ := e.Normalize("/api/users/550e8400-e29b-41d4-a716-446655440000/orders/17")
	if got := JoinTemplate(segs); got != "/api/users/{uuid}/orders/{int}" {
		t.Fatalf("restored template = %q", got)
	}
}

func obs(flowID, path, query string) Observation {
	return Observation{
		FlowID: flowID, Tenant: "acme", Host: "www.example.com",
		Method: "GET", Path: path, Query: query, Status: 200,
		Providers: []string{"cloudflare"},
		Seen:      time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC),
	}
}

func newTestAggregator() *Aggregator {
	return NewAggregator(DefaultCaps(), testOptions())
}

func TestCollapseMergesSiblingEndpoints(t *testing.T) {
	a := newTestAggregator()
	for i := 0; i < 20; i++ {
		a.Observe(obs(fmt.Sprintf("f%d", i), fmt.Sprintf("/job/%d", 8584280+i), ""))
	}
	dirty, retired := a.Collect()

	var templates []string
	var total int64
	for _, ep := range dirty {
		templates = append(templates, ep.PathTemplate)
		total += ep.Observations
	}
	if len(templates) != 1 || templates[0] != "/job/{int}" {
		t.Fatalf("dirty templates = %v, want exactly [/job/{int}]", templates)
	}
	if total != 20 {
		t.Fatalf("merged observations = %d, want 20 (siblings folded in)", total)
	}
	if len(retired) == 0 {
		t.Fatalf("expected retired endpoint IDs from the merge, got none")
	}
	// The path parameter must exist and be an int.
	ep := dirty[0]
	var pathParam *ParamProfile
	for _, pp := range ep.Params {
		if pp.Location == LocationPath {
			pathParam = pp
		}
	}
	if pathParam == nil || pathParam.Type != TypeInt {
		t.Fatalf("path param = %+v, want inferred int", pathParam)
	}
}

func TestDuplicateFlowIDsAreCountedOnce(t *testing.T) {
	a := newTestAggregator()
	for i := 0; i < 3; i++ {
		a.Observe(obs("same-flow", "/orders", "state=open"))
	}
	dirty, _ := a.Collect()
	if len(dirty) != 1 || dirty[0].Observations != 1 {
		t.Fatalf("observations = %+v, want a single counted observation", dirty)
	}
	if s := a.Stats(); s.Deduplicated != 2 {
		t.Fatalf("deduplicated = %d, want 2", s.Deduplicated)
	}
}

func TestQueryParamsAreProfiled(t *testing.T) {
	a := newTestAggregator()
	a.Observe(obs("f1", "/search", "q=shoes&page=1"))
	a.Observe(obs("f2", "/search", "q=boots&page=2"))
	a.Observe(obs("f3", "/search", "page=3"))
	dirty, _ := a.Collect()
	ep := dirty[0]

	q := ep.Params[paramKey(LocationQuery, "q")]
	if q == nil || q.Type != TypeAlnum {
		t.Fatalf("param q = %+v, want alnum", q)
	}
	if q.PresentCount != 2 || q.Observations != 3 {
		t.Fatalf("param q presence = %d/%d, want 2/3 (absence counts)", q.PresentCount, q.Observations)
	}
	page := ep.Params[paramKey(LocationQuery, "page")]
	if page == nil || page.Type != TypeInt || page.PresentCount != 3 {
		t.Fatalf("param page = %+v, want int present 3x", page)
	}
	if ep.MaxParamCount == nil || *ep.MaxParamCount != 2 {
		t.Fatalf("MaxParamCount = %v, want 2", ep.MaxParamCount)
	}
	// Ceilings that cannot be measured yet must stay nil, not zero.
	if ep.MaxHeaderCount != nil || ep.MaxCookieCount != nil || ep.MaxRequestBytes != nil {
		t.Fatalf("unmeasured ceilings must be nil: %+v", ep)
	}
}

// TestSecretsNeverEnterEnumValues is the test that stops the profiler becoming
// a secret-exfiltration path: a JWT in a query string may be counted but its
// value must never be stored.
func TestSecretsNeverEnterEnumValues(t *testing.T) {
	a := newTestAggregator()
	// Assembled at runtime so no JWT-shaped literal sits in the source for a
	// secret scanner to flag; the joined value still matches the detector the
	// profiler itself uses.
	jwt := strings.Join([]string{"eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiIxMjM0NTY3ODkwIn0", "dozjgNryP4J3jVmNHl0w5N"}, ".")
	a.Observe(obs("f1", "/callback", "token="+jwt+"&state=ok"))
	dirty, _ := a.Collect()
	ep := dirty[0]

	tok := ep.Params[paramKey(LocationQuery, "token")]
	if tok == nil {
		t.Fatal("token param not profiled")
	}
	for v := range tok.EnumValues {
		if v == jwt {
			t.Fatal("JWT value was stored in enum candidates")
		}
	}
	if tok.PresentCount != 1 {
		t.Fatalf("token still counted: present = %d, want 1", tok.PresentCount)
	}
	if s := a.Stats(); s.SecretsSeen != 1 {
		t.Fatalf("secrets_withheld = %d, want 1", s.SecretsSeen)
	}
}

func TestEnumOverflowDropsValuesKeepsBounds(t *testing.T) {
	caps := DefaultCaps()
	caps.EnumValues = 4
	a := NewAggregator(caps, testOptions())
	for i := 0; i < 10; i++ {
		a.Observe(obs(fmt.Sprintf("f%d", i), "/lookup", fmt.Sprintf("ref=value%02d", i)))
	}
	dirty, _ := a.Collect()
	ref := dirty[0].Params[paramKey(LocationQuery, "ref")]
	if !ref.EnumOverflowed || ref.EnumValues != nil {
		t.Fatalf("enum should have overflowed and dropped values: %+v", ref)
	}
	if ref.DistinctEstimate < 4 {
		t.Fatalf("distinct estimate = %d, want floor of at least the cap", ref.DistinctEstimate)
	}
	if ref.MaxLen != len("value09") {
		t.Fatalf("bounds must survive overflow: MaxLen = %d", ref.MaxLen)
	}
}

// TestShuffledReplayConverges: the same observations in any order must yield
// the same template set with the same totals (Constitution VI) — for
// homogeneous positions. A position mixing a literal route into a mostly-typed
// one sits on a decision boundary where an online algorithm may cluster either
// way depending on arrival order; that case is covered by the deterministic
// TestLiteralSiblingSurvivesTypedCollapse instead. Presence denominators also
// legitimately depend on when a parameter was first seen, so the assertion
// covers the order-independent facts.
func TestShuffledReplayConverges(t *testing.T) {
	var base []Observation
	for i := 0; i < 40; i++ {
		base = append(base, obs(fmt.Sprintf("job%d", i), fmt.Sprintf("/job/%d", 8500000+i), "src=list"))
	}
	for i := 0; i < 10; i++ {
		base = append(base, obs(fmt.Sprintf("s%d", i), "/health", "q=engineer"))
	}

	type outcome map[string]int64 // template -> observations
	runOnce := func(seed int64) outcome {
		observations := make([]Observation, len(base))
		copy(observations, base)
		rand.New(rand.NewSource(seed)).Shuffle(len(observations), func(i, j int) {
			observations[i], observations[j] = observations[j], observations[i]
		})
		a := newTestAggregator()
		for _, o := range observations {
			a.Observe(o)
		}
		dirty, _ := a.Collect()
		out := outcome{}
		for _, ep := range dirty {
			out[ep.Method+" "+ep.PathTemplate] += ep.Observations
		}
		return out
	}

	first := runOnce(1)
	if first["GET /job/{int}"] != 40 || first["GET /health"] != 10 {
		t.Fatalf("unexpected baseline outcome: %v", first)
	}
	for seed := int64(2); seed <= 6; seed++ {
		got := runOnce(seed)
		if fmt.Sprint(sortedOutcome(got)) != fmt.Sprint(sortedOutcome(first)) {
			t.Fatalf("seed %d diverged: %v vs %v", seed, got, first)
		}
	}
}

func sortedOutcome(m map[string]int64) []string {
	out := make([]string, 0, len(m))
	for k, v := range m {
		out = append(out, fmt.Sprintf("%s=%d", k, v))
	}
	sort.Strings(out)
	return out
}

func TestTenantConfigHostMatching(t *testing.T) {
	c := TenantConfig{Enabled: true, Hosts: []string{"api.example.com", "*.shop.example.com"}}
	cases := map[string]bool{
		"api.example.com":       true,
		"API.example.com:8443":  true,
		"www.example.com":       false,
		"eu.shop.example.com":   true,
		"shop.example.com":      true,
		"evilshop.example.com":  false,
		"a.b.shop.example.com":  true,
		"shop.example.com.evil": false,
		"":                      false,
	}
	for host, want := range cases {
		if got := c.MatchHost(host); got != want {
			t.Errorf("MatchHost(%q) = %v, want %v", host, got, want)
		}
	}
	disabled := TenantConfig{Enabled: false, Hosts: []string{"api.example.com"}}
	if disabled.MatchHost("api.example.com") {
		t.Error("disabled config must match nothing")
	}
}

func TestTenantConfigValidation(t *testing.T) {
	good := TenantConfig{Enabled: true, Hosts: []string{"a.example.com", "*.b.example.com"},
		ExcludePaths: []string{"/health"}}
	if err := good.Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	for _, bad := range []TenantConfig{
		{Hosts: []string{"https://a.example.com/x"}},
		{Hosts: []string{"a.*.example.com"}},
		{Hosts: []string{"**.example.com"}},
		{Hosts: []string{""}},
		{ExcludePaths: []string{"health"}},
		{MinObservationsToPublish: -1},
	} {
		if err := bad.Validate(); err == nil {
			t.Errorf("config %+v should have been rejected", bad)
		}
	}
}

// TestShapeCeilingsAreMonotonicMaxima: measured shape facts ratchet upward;
// an observation without them leaves the learned ceilings untouched rather
// than resetting or zeroing them.
func TestShapeCeilingsAreMonotonicMaxima(t *testing.T) {
	a := newTestAggregator()

	small := obs("f1", "/checkout", "")
	rb1, hc1, cc1 := int64(900), 12, 2
	small.RequestBytes, small.HeaderCount, small.CookieCount = &rb1, &hc1, &cc1
	small.CookieNames = []string{"session"}
	a.Observe(small)

	big := obs("f2", "/checkout", "")
	rb2, cc2 := int64(4200), 5
	big.RequestBytes, big.CookieCount = &rb2, &cc2
	big.CookieNames = []string{"session", "_ga"}
	a.Observe(big)

	a.Observe(obs("f3", "/checkout", "")) // no shape shipped at all

	dirty, _ := a.Collect()
	ep := dirty[0]
	if ep.MaxRequestBytes == nil || *ep.MaxRequestBytes != 4200 {
		t.Fatalf("max request bytes = %v, want 4200", ep.MaxRequestBytes)
	}
	if ep.MaxHeaderCount == nil || *ep.MaxHeaderCount != 12 {
		t.Fatalf("max header count = %v, want 12 (kept from the earlier observation)", ep.MaxHeaderCount)
	}
	if ep.MaxCookieCount == nil || *ep.MaxCookieCount != 5 {
		t.Fatalf("max cookie count = %v, want 5", ep.MaxCookieCount)
	}
	if len(ep.CookieNames) != 2 || !ep.CookieNames["session"] || !ep.CookieNames["_ga"] {
		t.Fatalf("cookie names = %v", ep.CookieNames)
	}
	// HeaderBytes was never measured: it must be nil, not zero.
	if ep.MaxHeaderBytes != nil {
		t.Fatalf("header bytes was never shipped, must stay nil: %v", ep.MaxHeaderBytes)
	}
}

func TestCookieNameCapSetsTruncated(t *testing.T) {
	caps := DefaultCaps()
	caps.CookieNames = 2
	a := NewAggregator(caps, testOptions())
	o := obs("f1", "/home", "")
	o.CookieNames = []string{"a", "b", "c", "d"}
	a.Observe(o)
	dirty, _ := a.Collect()
	if len(dirty[0].CookieNames) != 2 || !dirty[0].Truncated {
		t.Fatalf("cap must hold names at 2 and mark truncated: %v truncated=%v",
			dirty[0].CookieNames, dirty[0].Truncated)
	}
}

func TestEndpointCapRefusesNewButKeepsLearning(t *testing.T) {
	caps := DefaultCaps()
	caps.EndpointsPerHost = 2
	caps.EndpointsPerTenant = 2
	a := NewAggregator(caps, testOptions())
	a.Observe(obs("f1", "/a", ""))
	a.Observe(obs("f2", "/b", ""))
	a.Observe(obs("f3", "/c", "")) // refused: cap
	a.Observe(obs("f4", "/a", "")) // existing endpoint keeps learning
	dirty, _ := a.Collect()
	if len(dirty) != 2 {
		t.Fatalf("endpoints = %d, want cap of 2", len(dirty))
	}
	if s := a.Stats(); s.CapHits != 1 {
		t.Fatalf("cap hits = %d, want 1", s.CapHits)
	}
	for _, ep := range dirty {
		if ep.PathTemplate == "/a" && ep.Observations != 2 {
			t.Fatalf("/a observations = %d, want 2", ep.Observations)
		}
	}
}

// TestParamsSerialiseWithoutNULEscape reproduces the production flush failure:
// a NUL byte in a parameter key or value marshals to the \u0000 escape, which
// PostgreSQL jsonb rejects (SQLSTATE 22P05), silently failing every flush. The
// params column must never contain that escape, even for scanner traffic that
// plants NUL bytes in parameter names and values.
func TestParamsSerialiseWithoutNULEscape(t *testing.T) {
	a := newTestAggregator()
	nul := string([]byte{0})
	query := "page=2&na" + nul + "me=x&q=a" + nul + "b"
	a.Observe(obs("f1", "/search", query))

	dirty, _ := a.Collect()
	if len(dirty) == 0 {
		t.Fatal("no endpoints collected")
	}
	nulEscape := string([]byte{92, 117, 48, 48, 48, 48})
	for _, ep := range dirty {
		// Exactly what profilerepo marshals before the jsonb upsert.
		for _, v := range []any{ep.Params, ep.StatusMix} {
			b, err := json.Marshal(v)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if strings.Contains(string(b), nulEscape) {
				t.Fatalf("serialised jsonb value contains the rejected NUL escape: %s", b)
			}
		}
	}
}

func TestStripNULAndSeparator(t *testing.T) {
	if got := stripNUL("clean"); got != "clean" {
		t.Fatalf("clean string altered: %q", got)
	}
	if got := stripNUL("a" + string([]byte{0}) + "b"); got != "ab" {
		t.Fatalf("stripNUL did not remove NUL: %q", got)
	}
	if strings.IndexByte(paramKey(LocationQuery, "p"), 0) >= 0 {
		t.Fatal("paramKey still uses a NUL separator")
	}
}

func TestBodyParamsObservedAsBodyLocation(t *testing.T) {
	a := newTestAggregator()
	for i := 0; i < 30; i++ {
		o := Observation{
			FlowID: fmt.Sprintf("b%d", i), Tenant: "acme", Host: "www.example.com",
			Method: "POST", Path: "/apply", Status: 200,
			Providers: []string{"f5asm"},
			Seen:      time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC),
			Body:      "job_id=42&cv=hello&page=2",
		}
		a.Observe(o)
	}
	dirty, _ := a.Collect()
	var ep *EndpointProfile
	for _, e := range dirty {
		if e.PathTemplate == "/apply" && e.Method == "POST" {
			ep = e
		}
	}
	if ep == nil {
		t.Fatal("no /apply endpoint")
	}
	got := map[string]ParamLocation{}
	for _, pp := range ep.Params {
		got[pp.Name] = pp.Location
	}
	for _, name := range []string{"job_id", "cv", "page"} {
		if got[name] != LocationBody {
			t.Fatalf("param %q location = %q, want body (params: %v)", name, got[name], got)
		}
	}
	if ep.MaxParamCount == nil || *ep.MaxParamCount != 3 {
		t.Fatalf("MaxParamCount = %v, want 3", ep.MaxParamCount)
	}
}

func TestNormalizeParamNameFoldsArrayIndices(t *testing.T) {
	cases := map[string]string{
		"consent[335045]":   "consent[]",
		"consent[336191]":   "consent[]",
		"categories[]":      "categories[]",
		"data[0][1]":        "data[][]",
		"filters[category]": "filters[category]", // named key kept
		"job_sid":           "job_sid",
		"x[550e8400-e29b-41d4-a716-446655440000]": "x[]",
	}
	for in, want := range cases {
		if got := NormalizeParamName(in); got != want {
			t.Errorf("NormalizeParamName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestArrayIndexParamsMergeToOne(t *testing.T) {
	a := newTestAggregator()
	for i := 0; i < 40; i++ {
		o := Observation{
			FlowID: fmt.Sprintf("c%d", i), Tenant: "acme", Host: "www.example.com",
			Method: "POST", Path: "/consent", Status: 200, Providers: []string{"f5asm"},
			Seen: time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC),
			// each request carries a different set of numeric-id array keys
			Body: fmt.Sprintf("job_sid=5&consent[%d]=1&consent[%d]=1", 335000+i, 336000+i),
		}
		a.Observe(o)
	}
	dirty, _ := a.Collect()
	var ep *EndpointProfile
	for _, e := range dirty {
		if e.PathTemplate == "/consent" {
			ep = e
		}
	}
	if ep == nil {
		t.Fatal("no /consent endpoint")
	}
	names := map[string]bool{}
	for _, pp := range ep.Params {
		names[pp.Name] = true
	}
	if !names["consent[]"] || !names["job_sid"] {
		t.Fatalf("expected consent[] and job_sid, got %v", names)
	}
	// consent[<id>] must NOT appear as distinct params
	for n := range names {
		if n != "consent[]" && n != "job_sid" {
			t.Fatalf("unexpected distinct param %q (array indices not folded)", n)
		}
	}
	if ep.Truncated {
		t.Fatal("endpoint should not be truncated after folding array indices")
	}
}
