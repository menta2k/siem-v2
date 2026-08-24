package victorialogs

import (
	"strings"

	"github.com/menta2k/siem-v2/backend/internal/biz/flow"
	"github.com/menta2k/siem-v2/backend/internal/normalize/schema"
)

// WAF-migration rollups indexed on the flow document.
//
// The migration stages compare, per correlated request, what F5 decided against
// what Cloudflare decided — and which Cloudflare rules MATCHED (including
// log-mode rules that matched without blocking). Those facts live inside each
// event's verdict.reason_raw JSON, which is not queryable. These helpers hoist
// them into space-joined index fields, exactly as ray_ids/providers are, so a
// windowed query can filter and count by them.

// wafVerdict maps a normalized action to the three-word migration vocabulary:
// blocked | monitored | allowed. Empty means the vendor had no event on the flow.
func wafVerdict(action schema.Action) string {
	switch action {
	case schema.ActionBlocked, schema.ActionChallengeFailed, schema.ActionRateLimited:
		return "blocked"
	case schema.ActionLogged:
		return "monitored"
	case "":
		return ""
	default:
		return "allowed"
	}
}

// f5Event returns the flow's F5 ASM event, or nil.
func f5Event(f *flow.Flow) *schema.Event {
	for i := range f.Events {
		if f.Events[i].Provider == schema.ProviderF5ASM {
			return &f.Events[i]
		}
	}
	return nil
}

// cfEdgeEvent returns the Cloudflare edge event that carries the security
// decision. A Worker flow has two edge records (visitor + subrequest); prefer
// whichever carries matched rules or a non-allow action, else the first.
func cfEdgeEvent(f *flow.Flow) *schema.Event {
	var first *schema.Event
	for i := range f.Events {
		e := &f.Events[i]
		if e.Provider != schema.ProviderCloudflare || e.Layer != schema.LayerEdge {
			continue
		}
		if first == nil {
			first = e
		}
		if len(cfMatchedRuleIDs(e)) > 0 || e.Verdict.Action != schema.ActionAllowed {
			return e
		}
	}
	return first
}

// wafIndexFields derives the four migration index fields from a flow's F5 and
// Cloudflare-edge events.
func wafIndexFields(f *flow.Flow) (f5Verdict, cfVerdict, f5Violations, cfMatchedRules string) {
	if e := f5Event(f); e != nil {
		f5Verdict = wafVerdict(e.Verdict.Action)
		f5Violations = strings.Join(f5ViolationTokens(e), " ")
	}
	if e := cfEdgeEvent(f); e != nil {
		cfVerdict = wafVerdict(e.Verdict.Action)
		cfMatchedRules = strings.Join(cfMatchedRuleIDs(e), " ")
	}
	return
}

// f5ViolationTokens turns F5's comma-separated reason_raw.violations into
// slugged, de-duplicated tokens ("Illegal query string length" ->
// "illegal_query_string_length") so a word filter can hit an individual one.
func f5ViolationTokens(e *schema.Event) []string {
	raw, _ := e.Verdict.ReasonRaw["violations"].(string)
	if raw == "" || raw == "N/A" {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, v := range strings.Split(raw, ",") {
		t := slugToken(v)
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
	}
	return out
}

// cfMatchedRuleIDs returns every Cloudflare rule id that matched the request —
// the reason_raw.SecurityRuleIDs array (which includes log-mode matches), or the
// single deciding rule id as a fallback.
func cfMatchedRuleIDs(e *schema.Event) []string {
	if v, ok := e.Verdict.ReasonRaw["SecurityRuleIDs"]; ok {
		if ids := toStringSlice(v); len(ids) > 0 {
			return ids
		}
	}
	if e.Verdict.RuleID != "" {
		return []string{e.Verdict.RuleID}
	}
	return nil
}

func toStringSlice(v any) []string {
	switch t := v.(type) {
	case []string:
		return nonEmpty(t)
	case []any:
		out := make([]string, 0, len(t))
		for _, x := range t {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return nonEmpty(out)
	}
	return nil
}

func nonEmpty(in []string) []string {
	out := in[:0:0]
	for _, s := range in {
		if strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return out
}

// slugToken lowercases and collapses non-alphanumeric runs to single
// underscores, producing a single word-matchable token.
func slugToken(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	underscore := false
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			underscore = false
		} else if !underscore {
			b.WriteByte('_')
			underscore = true
		}
	}
	return strings.Trim(b.String(), "_")
}
