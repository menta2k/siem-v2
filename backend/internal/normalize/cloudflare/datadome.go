package cloudflare

import (
	"strings"
	"time"

	"github.com/menta2k/siem-v2/backend/internal/correlate/keys"
	"github.com/menta2k/siem-v2/backend/internal/normalize"
	"github.com/menta2k/siem-v2/backend/internal/normalize/schema"
)

// DataDome's Cloudflare integration works by a Worker calling DataDome's
// protection API for every request it guards. Cloudflare logs that call as an
// ordinary SUBREQUEST, so the http_requests dataset carries one extra row per
// protected request.
//
// Read literally those rows are noise: a POST to api-cloudflare.datadome.co from
// Cloudflare's own egress. Read correctly they are DataDome's verdict — and the
// only one available, because DataDome's own export identifies requests by a
// private id that carries no Ray ID at all.
const dataDomeHost = "api-cloudflare.datadome.co"

// noParentRay is what Cloudflare writes in ParentRayID for a top-level request.
//
// It is the literal string "00", NOT an empty string. Treating it as a real ray
// would key every top-level request in the tenant onto one shared identifier and
// merge the entire tenant's traffic into a single flow.
const noParentRay = "00"

// The protection API's answer. The status says whether DataDome ENFORCED its
// decision; the response type says WHAT that decision was. Neither alone is
// enough, and the difference matters in the dangerous direction.
const (
	dataDomeServed   = 200
	dataDomeEnforced = 403
)

// The values DataDome sends, taken from live traffic rather than documentation.
const (
	dataDomeAuthorize = "authorize"
	// interstitial is the Device Check: a JavaScript challenge the client may pass.
	dataDomeInterstitial = "interstitial"
	// BLOCK IS A CHALLENGE. It is DataDome's name for the slider CAPTCHA — the one
	// value in this vocabulary whose name means the opposite of what it does.
	// Mapping it to "blocked" would overstate enforcement across a large share of
	// traffic.
	dataDomeBlockChallenge = "block"
	// hard_block is the actual block.
	dataDomeHardBlock = "hard_block"
)

// parentRay returns the ray of the request this one was made while handling.
func parentRay(r record) string {
	parent := strings.TrimSpace(r.ParentRayID)
	if parent == noParentRay {
		return ""
	}
	return parent
}

// IsDataDomeCall reports whether a record is the Worker's call to DataDome
// rather than a request from a real client.
//
// Both conditions are required. The hostname alone would also match a genuine
// visitor browsing that domain, and a parent ray is only ever present on a
// subrequest — together they identify exactly "a call made while handling some
// other request".
func isDataDomeCall(r record) bool {
	if !strings.EqualFold(strings.TrimSpace(r.ClientRequestHost), dataDomeHost) {
		return false
	}
	return parentRay(r) != ""
}

// dataDomeVerdict maps the protection API's answer onto the common vocabulary.
//
// It takes BOTH inputs. DataDome's documentation states the header reports "the
// response type applied by DataDome OR THE TYPE THAT WOULD HAVE BEEN APPLIED if
// protection was enabled" — so a hard_block on a 200 is DataDome reporting what
// it WOULD have done. Reading that as blocked invents a block that never
// happened, which is the same error as missing one, pointed the other way.
func dataDomeVerdict(status int, responseType string) (schema.Action, bool) {
	decision := strings.ToLower(strings.TrimSpace(responseType))

	switch status {
	case dataDomeServed:
		// Served. The type describes what DataDome decided, not what the visitor got.
		switch decision {
		case dataDomeInterstitial, dataDomeBlockChallenge, dataDomeHardBlock:
			// Detection without enforcement — the request was served anyway.
			return schema.ActionLogged, true
		case dataDomeAuthorize, "":
			return schema.ActionAllowed, true
		default:
			// An unrecognised type must land on the old behaviour rather than on no
			// verdict: this vocabulary will grow.
			return schema.ActionAllowed, false
		}

	case dataDomeEnforced:
		// Enforced. Now the type decides which of the three a 403 actually was.
		switch decision {
		case dataDomeHardBlock:
			return schema.ActionBlocked, true
		case dataDomeInterstitial, dataDomeBlockChallenge:
			return schema.ActionChallenged, true
		default:
			// Lossy fallback for records written before Logs Enrichment, and for
			// values nobody has mapped yet. It cannot separate a Device Check from a
			// hard block, and errs toward challenged.
			return schema.ActionChallenged, decision == ""
		}

	default:
		// 499 and friends: the client went away before the answer was delivered.
		// DataDome did decide, but Cloudflare never saw which way — and unknown must
		// never mask a real block.
		return schema.ActionUnknown, false
	}
}

// deriveDataDome turns the Worker's subrequest into DataDome's verdict on the
// request that triggered it.
//
// The whole design rests on ParentRayID. It is the ray of the ORIGINAL request,
// so using it as the correlation identifier makes this event join the Cloudflare,
// F5 and nginx records of that same request through the EXISTING exact tier — no
// new machinery, no time window, no heuristic.
func deriveDataDome(r record, receivedAt time.Time) *schema.Event {
	parent := parentRay(r)
	responseType := headerLookup(r, trafficRuleResponseHeader)
	action, mapped := dataDomeVerdict(r.EdgeResponseStatus, responseType)

	start, _ := parseTimestamp(r.EdgeStartTimestamp)

	bot := &schema.Event{
		SchemaVersion: schema.Version,
		// The raw id is the subrequest's own ray: two DataDome calls are two
		// records even when they concern the same parent.
		RawID: "cf:" + r.RayID,
		// The event id is keyed on the PARENT ray, because this event describes
		// the original request rather than the subrequest that carried the answer.
		EventID:              "dd:" + parent,
		Provider:             schema.ProviderDataDome,
		Dataset:              "cloudflare_worker_subrequest",
		ParserVersion:        parserVersion,
		VendorRequestID:      r.RayID,
		RayID:                parent,
		CorrelationKeySource: schema.KeySourceRayID,
		EventTime:            start,
		ReceivedAt:           receivedAt,
		Layer:                schema.LayerBotManagement,
		Client: schema.Client{
			IP: r.ClientIP, ASN: r.ClientASN,
			Country: strings.ToUpper(r.ClientCountry),
		},
	}
	if id, ok := keys.NewIdentifier(keys.NSRayID, parent); ok {
		bot.Identifiers = []string{id.String()}
	}
	if order, ok := bot.Layer.Order(); ok {
		bot.LayerOrderHint = order
	}

	bot.Verdict = schema.Verdict{
		Action:      action,
		Terminating: action.Terminal(),
		Mapped:      mapped,
		ReasonRaw: map[string]any{
			trafficRuleResponseHeader: responseType,
			"subrequest_status":       r.EdgeResponseStatus,
			"subrequest_ray":          r.RayID,
			"parent_ray":              parent,
			"source":                  "cloudflare worker subrequest to " + dataDomeHost,
		},
	}
	if !mapped {
		bot.AddFlag(schema.FlagUnmappedValues)
	}
	bot.Bot = &schema.Bot{DataDomePresent: true, DataDomeAction: responseType}

	normalize.ApplyTimeQuality(bot)
	return bot
}

const trafficRuleResponseHeader = "x-datadome-traffic-rule-response"
