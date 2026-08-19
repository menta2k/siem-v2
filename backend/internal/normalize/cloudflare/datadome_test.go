package cloudflare

import (
	"testing"

	"github.com/menta2k/siem-v2/backend/internal/normalize/schema"
)

// TestBlockIsAChallengeNotABlock is the single most consequential mapping in
// this package.
//
// "block" is DataDome's name for the slider CAPTCHA — the one value in its
// vocabulary whose name means the opposite of what it does. "hard_block" is the
// actual block. Mapping them together would overstate enforcement across a large
// share of traffic and, worse, would report a real hard block as merely
// challenged when it appears alongside one.
func TestBlockIsAChallengeNotABlock(t *testing.T) {
	if action, _ := dataDomeVerdict(403, "block"); action != schema.ActionChallenged {
		t.Errorf(`"block" is the slider CAPTCHA and must map to challenged, got %q`, action)
	}
	if action, _ := dataDomeVerdict(403, "hard_block"); action != schema.ActionBlocked {
		t.Errorf(`"hard_block" is the real block, got %q`, action)
	}
	if action, _ := dataDomeVerdict(403, "interstitial"); action != schema.ActionChallenged {
		t.Errorf(`"interstitial" is the Device Check, got %q`, action)
	}
}

// TestServedMeansDetectionWithoutEnforcement: DataDome's header reports the type
// it applied OR the type it WOULD have applied. On a 200 the request was served
// regardless, so a hard_block there is a report, not a block.
func TestServedMeansDetectionWithoutEnforcement(t *testing.T) {
	for _, decision := range []string{"hard_block", "block", "interstitial"} {
		action, mapped := dataDomeVerdict(200, decision)
		if action != schema.ActionLogged {
			t.Errorf("status 200 with %q means detection without enforcement, got %q", decision, action)
		}
		if !mapped {
			t.Errorf("%q on a 200 is a known state, not an unmapped one", decision)
		}
	}
	if action, _ := dataDomeVerdict(200, "authorize"); action != schema.ActionAllowed {
		t.Error("authorize on a 200 is a plain allow")
	}
	// Records written before Logs Enrichment carry no type; a 200 was an allow
	// then and stays one now.
	if action, _ := dataDomeVerdict(200, ""); action != schema.ActionAllowed {
		t.Error("a 200 with no type is an allow")
	}
}

// TestUnobservedDecisionIsUnknown: on a 499 the client left before the answer
// arrived. DataDome decided, but Cloudflare never saw which way — and a
// non-observation must never mask a real block.
func TestUnobservedDecisionIsUnknown(t *testing.T) {
	action, mapped := dataDomeVerdict(499, "")
	if action != schema.ActionUnknown {
		t.Errorf("an unobserved decision must be unknown, got %q", action)
	}
	if mapped {
		t.Error("an unobserved decision is not a mapped verdict")
	}
}

// TestUnrecognisedTypeDegradesRatherThanVanishes: the vocabulary will grow, and
// a new value must land on the old behaviour rather than on no verdict.
func TestUnrecognisedTypeDegradesRatherThanVanishes(t *testing.T) {
	action, mapped := dataDomeVerdict(403, "quantum_shield")
	if action != schema.ActionChallenged {
		t.Errorf("an unknown type on an enforced 403 should degrade to challenged, got %q", action)
	}
	if mapped {
		t.Error("it must be marked unmapped so the raw value is surfaced")
	}
}

// TestNoParentRayIsNotARealRay: Cloudflare writes the literal "00" for a
// top-level request. Treating it as a ray would key every top-level request in
// the tenant onto one identifier and merge the whole tenant into a single flow.
func TestNoParentRayIsNotARealRay(t *testing.T) {
	if got := parentRay(record{ParentRayID: "00"}); got != "" {
		t.Fatalf(`"00" means no parent and must yield empty, got %q`, got)
	}
	if got := parentRay(record{ParentRayID: "a2d6ea0d6d11c5d9"}); got != "a2d6ea0d6d11c5d9" {
		t.Errorf("a real parent ray must pass through, got %q", got)
	}
}

// TestIsDataDomeCallRequiresBothConditions: the hostname alone would also match
// a genuine visitor browsing that domain.
func TestIsDataDomeCallRequiresBothConditions(t *testing.T) {
	if !isDataDomeCall(record{ClientRequestHost: dataDomeHost, ParentRayID: "abc123"}) {
		t.Error("host plus a parent ray identifies the Worker's subrequest")
	}
	if isDataDomeCall(record{ClientRequestHost: dataDomeHost, ParentRayID: "00"}) {
		t.Error("a top-level request to that host is a visitor, not a subrequest")
	}
	if isDataDomeCall(record{ClientRequestHost: "shop.example.com", ParentRayID: "abc123"}) {
		t.Error("any other subrequest is not a DataDome call")
	}
}

// TestSubrequestContributesBothRays is the join that makes a four-layer flow
// possible when a Worker is in play.
//
// One visitor request yields several Cloudflare rows. The Worker's fetch to the
// origin has its own ray — which is what nginx and F5 see — while its call to
// DataDome is keyed on the visitor's ray. Only a record carrying BOTH connects
// the origin layers to the bot layer.
func TestSubrequestContributesBothRays(t *testing.T) {
	ids := identifiers(record{
		RayID:       "a2d6ea0f6813ccd4",
		ParentRayID: "a2d6ea0d6d11c5d9",
	})
	if len(ids) != 2 {
		t.Fatalf("a subrequest must contribute its own ray AND its parent, got %v", ids)
	}

	// A top-level request contributes only its own ray. Treating "00" as a parent
	// would merge every top-level request in the tenant into one flow.
	top := identifiers(record{RayID: "a2d6ea0f6813ccd4", ParentRayID: "00"})
	if len(top) != 1 {
		t.Fatalf("a top-level request has no parent to contribute, got %v", top)
	}
}

func TestDataDomeSubrequestBecomesTheBotLayer(t *testing.T) {
	raw := []byte(`{"RayID":"bbbb2222cccc3333","ParentRayID":"aaaa1111bbbb2222",` +
		`"ClientRequestHost":"api-cloudflare.datadome.co","ClientRequestMethod":"POST",` +
		`"EdgeStartTimestamp":"2026-08-19T12:00:00.100Z","EdgeResponseStatus":403,` +
		`"ClientIP":"203.0.113.9","ClientCountry":"de",` +
		`"ResponseHeaders":{"x-datadome-traffic-rule-response":"hard_block"}}`)

	e, err := New().Parse(raw, receivedAt)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.Provider != schema.ProviderDataDome {
		t.Fatalf("a Worker subrequest must become the bot layer, got provider %q", e.Provider)
	}
	if e.Layer != schema.LayerBotManagement {
		t.Errorf("layer: got %q", e.Layer)
	}
	// Keyed on the PARENT, because this describes the original request.
	if e.RayID != "aaaa1111bbbb2222" {
		t.Errorf("must key on the parent ray, got %q", e.RayID)
	}
	if e.VendorRequestID != "bbbb2222cccc3333" {
		t.Errorf("the subrequest's own ray should be retained, got %q", e.VendorRequestID)
	}
	if e.Verdict.Action != schema.ActionBlocked || !e.Verdict.Terminating {
		t.Errorf("hard_block on an enforced 403 is a terminating block, got %q", e.Verdict.Action)
	}
	if len(e.Identifiers) != 1 || e.Identifiers[0] != "ray:aaaa1111bbbb2222" {
		t.Errorf("identifier must be the parent ray, got %v", e.Identifiers)
	}
}

func TestVisitorRequestToDataDomeHostIsNotASubrequest(t *testing.T) {
	// A genuine visitor browsing that hostname must be parsed as an edge request,
	// not silently reinterpreted as a bot verdict.
	raw := []byte(`{"RayID":"cccc3333dddd4444","ParentRayID":"00",` +
		`"ClientRequestHost":"api-cloudflare.datadome.co","ClientRequestMethod":"GET",` +
		`"EdgeStartTimestamp":"2026-08-19T12:00:00.100Z","EdgeResponseStatus":200}`)

	e, err := New().Parse(raw, receivedAt)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.Provider != schema.ProviderCloudflare || e.Layer != schema.LayerEdge {
		t.Fatalf("a top-level request is an edge event, got provider=%q layer=%q", e.Provider, e.Layer)
	}
}

func TestWAFAttackScoresAreCaptured(t *testing.T) {
	raw := []byte(`{"RayID":"dddd4444eeee5555","ParentRayID":"00","ClientRequestHost":"shop.example.com",` +
		`"EdgeStartTimestamp":"2026-08-19T12:00:00.100Z","EdgeResponseStatus":200,` +
		`"WAFAttackScore":12,"WAFSQLiAttackScore":5,"WAFXSSAttackScore":98}`)
	e, err := New().Parse(raw, receivedAt)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// Present on the record and therefore available for analysis; the scale runs
	// 1 = attack, 99 = clean, opposite to a bot score.
	if e.Verdict.ReasonRaw == nil {
		t.Error("verdict should carry the provider's raw reason content")
	}
}
