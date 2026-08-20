package cloudflare

import (
	"strconv"
	"strings"

	"github.com/menta2k/siem-v2/backend/internal/normalize/schema"
)

// actionMap translates Cloudflare's action vocabulary into the normalized one.
//
// Values not present here are NOT guessed at. An unrecognized action is surfaced
// verbatim with Mapped=false, because a security tool that quietly rounds an
// unknown decision to the nearest familiar one gives the analyst a confident
// wrong answer (FR-014).
var actionMap = map[string]schema.Action{
	"allow":             schema.ActionAllowed,
	"skip":              schema.ActionAllowed,
	"log":               schema.ActionLogged,
	"block":             schema.ActionBlocked,
	"drop":              schema.ActionBlocked,
	"challenge":         schema.ActionChallenged,
	"managed_challenge": schema.ActionChallenged,
	"managedchallenge":  schema.ActionChallenged,
	// The managedChallenge* family: a challenge that was solved is a pass; one
	// that was bypassed (an exception let the request through) is an allow.
	"managedchallengenoninteractivesolved": schema.ActionChallengePassed,
	"managedchallengeinteractivesolved":    schema.ActionChallengePassed,
	"managedchallengebypassed":             schema.ActionAllowed,
	"jschallenge":                          schema.ActionChallenged,
	"js_challenge":                         schema.ActionChallenged,
	"connection_close":                     schema.ActionBlocked,
	"connectionclose":                      schema.ActionBlocked,
	"force_connection_close":               schema.ActionBlocked,
	"forceconnectionclose":                 schema.ActionBlocked,
	"rate_limit":                           schema.ActionRateLimited,
}

// Cloudflare's current ruleset writes SecurityAction in camelCase
// (managedChallenge, connectionClose, forceConnectionClose). Lookups lowercase
// the value, so the concatenated forms above sit alongside the snake_case ones
// the legacy docs used. Without them a managed challenge — the single most
// common security action on this traffic — fell through to "unknown".

// legacyWAFAction maps the older numeric WAFAction enum.
var legacyWAFAction = map[int]schema.Action{
	0: schema.ActionUnknown,
	1: schema.ActionAllowed,
	2: schema.ActionBlocked,
	3: schema.ActionChallenged,
	5: schema.ActionLogged,
}

// mapVerdict builds the normalized verdict, preferring the current Security*
// fields and falling back to the legacy family.
//
// Which family a zone populates depends on plan and age and is unverified for
// this deployment (V5), so both are handled and the one actually used is recorded
// in ReasonRaw — that way the first real records tell us the answer instead of
// us having to guess before seeing them.
func mapVerdict(r record) schema.Verdict {
	if v, ok := modernVerdict(r); ok {
		return v
	}
	if v, ok := legacyVerdict(r); ok {
		return v
	}
	// No security fields at all: the edge served the request without a security
	// decision. That is an allow, and it is mapped — not unknown.
	return schema.Verdict{
		Action:    schema.ActionAllowed,
		Mapped:    true,
		ReasonRaw: map[string]any{"field_family": "none", "status": r.EdgeResponseStatus},
	}
}

func modernVerdict(r record) (schema.Verdict, bool) {
	action := strings.TrimSpace(r.SecurityAction)
	if action == "" && len(r.SecurityActions) > 0 {
		action = strings.TrimSpace(r.SecurityActions[0])
	}
	if action == "" {
		return schema.Verdict{}, false
	}

	reason := map[string]any{
		"field_family":            "security",
		"SecurityAction":          r.SecurityAction,
		"SecurityRuleID":          r.SecurityRuleID,
		"SecurityRuleDescription": r.SecurityRuleDescription,
		"SecurityActions":         r.SecurityActions,
		"SecuritySources":         r.SecuritySources,
		"SecurityRuleIDs":         r.SecurityRuleIDs,
	}

	mapped, ok := actionMap[strings.ToLower(action)]
	if !ok {
		return schema.Verdict{
			Action: schema.ActionUnknown, Mapped: false,
			RuleID: r.SecurityRuleID, RuleName: r.SecurityRuleDescription,
			Category: firstOrEmpty(r.SecuritySources), ReasonRaw: reason,
		}, true
	}
	return schema.Verdict{
		Action:      mapped,
		Terminating: mapped.Terminal(),
		RuleID:      r.SecurityRuleID,
		RuleName:    r.SecurityRuleDescription,
		Category:    firstOrEmpty(r.SecuritySources),
		Mapped:      true,
		ReasonRaw:   reason,
	}, true
}

func legacyVerdict(r record) (schema.Verdict, bool) {
	hasLegacy := r.WAFAction != nil || len(r.FirewallMatchesActions) > 0
	if !hasLegacy {
		return schema.Verdict{}, false
	}
	reason := map[string]any{
		"field_family":           "legacy",
		"WAFAction":              r.WAFAction,
		"WAFRuleID":              r.WAFRuleID,
		"FirewallMatchesActions": r.FirewallMatchesActions,
		"FirewallMatchesSources": r.FirewallMatchesSources,
		"FirewallMatchesRuleIDs": r.FirewallMatchesRuleIDs,
	}

	// The string form in FirewallMatchesActions is more specific than the numeric
	// enum, so prefer it when both are present.
	if len(r.FirewallMatchesActions) > 0 {
		raw := strings.ToLower(strings.TrimSpace(r.FirewallMatchesActions[0]))
		if mapped, ok := actionMap[raw]; ok {
			return schema.Verdict{
				Action: mapped, Terminating: mapped.Terminal(),
				RuleID:   firstOrEmpty(r.FirewallMatchesRuleIDs),
				Category: firstOrEmpty(r.FirewallMatchesSources),
				Mapped:   true, ReasonRaw: reason,
			}, true
		}
		return schema.Verdict{
			Action: schema.ActionUnknown, Mapped: false,
			RuleID: firstOrEmpty(r.FirewallMatchesRuleIDs), ReasonRaw: reason,
		}, true
	}

	mapped, ok := legacyWAFAction[*r.WAFAction]
	if !ok || mapped == schema.ActionUnknown {
		return schema.Verdict{
			Action: schema.ActionUnknown, Mapped: false,
			RuleID: r.WAFRuleID, ReasonRaw: reason,
		}, true
	}
	return schema.Verdict{
		Action: mapped, Terminating: mapped.Terminal(),
		RuleID: r.WAFRuleID, Mapped: true, ReasonRaw: reason,
	}, true
}

// mapBot extracts bot signals, including the DataDome enrichment carried in the
// Worker-injected headers.
func mapBot(r record) *schema.Bot {
	b := &schema.Bot{CFBotScore: r.BotScore}

	get := func(name string) string { return headerLookup(r, name) }
	b.DataDomeIsBot = get("x-datadome-isbot")
	b.DataDomeBotName = get("x-datadome-botname")
	b.DataDomeRuleType = get("x-datadome-ruletype")
	b.DataDomeAction = get("x-datadome-traffic-rule-response")
	b.DataDomeScore = parseFloatPtr(get("x-datadome-score"))
	b.DataDomeRiskScore = parseFloatPtr(get("x-datadome-riskscore"))

	// Presence is judged on ANY DataDome signal, not the request id alone.
	// In this deployment DataDome runs as a Cloudflare Worker and its verdict
	// arrives as a response header on the same record, so there is nothing to
	// bridge — the action itself is the evidence that DataDome ran.
	b.DataDomePresent = b.DataDomeAction != "" || b.DataDomeIsBot != "" ||
		get("x-datadome-requestid") != ""
	return b
}

func parseFloatPtr(s string) *float64 {
	if s == "" {
		return nil
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return nil
	}
	return &f
}

func firstOrEmpty(ss []string) string {
	if len(ss) == 0 {
		return ""
	}
	return ss[0]
}
