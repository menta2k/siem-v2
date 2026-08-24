package victorialogs

import (
	"context"
	"fmt"
	"strings"
)

// ruleNameScanCap bounds how many recent flows a name lookup decodes. Names are
// decoration, so a generous-but-finite scan is right: enough to find a name for
// a rule that fires at all, cheap enough to run per page behind a cache.
const ruleNameScanCap = 500

// RuleNamesFor resolves Cloudflare rule ids to their descriptions, harvested
// from the ingested Logpush data itself — no Cloudflare API token required.
//
// A rule's name lives in the Cloudflare edge verdict (SecurityRuleDescription),
// not in an indexed flow field, so this decodes recent flows that reference the
// ids and reads the name off each one's edge event. Two sources, in priority
// order:
//
//   - the DECIDING rule: verdict.RuleID == id → verdict.RuleName is authoritative;
//   - a LOG-MODE match: on a flow whose edge matched exactly one rule and carries
//     a description, that description names that matched id (an enforced action
//     leaves rule_id empty, so this is the only name a log-mode rule ever gets).
//
// Newest flow wins, so a renamed rule surfaces its new name. Ids that never
// appear named stay unresolved — the caller degrades to the bare id.
func (r *FlowRepo) RuleNamesFor(ctx context.Context, tenant string, ids []string) (map[string]string, error) {
	if !safeValue.MatchString(tenant) || tenant == "" {
		return nil, &ErrUnsafeValue{Field: "tenant", Value: tenant}
	}
	want := map[string]bool{}
	var terms []string
	for _, id := range ids {
		if id == "" || want[id] || !safeValue.MatchString(id) {
			continue
		}
		want[id] = true
		terms = append(terms, "rule_id:="+quote(id), `cf_matched_rules:`+quote(id))
	}
	if len(terms) == 0 {
		return map[string]string{}, nil
	}

	q := fmt.Sprintf(`{tenant=%s,record_kind=%s} (%s) | sort by (_time desc) | limit %d`,
		quote(tenant), quote(string(KindFlow)), strings.Join(terms, " OR "), ruleNameScanCap)
	rows, err := r.client.Query(ctx, r.tenant, q, ruleNameScanCap)
	if err != nil {
		return nil, err
	}

	out := map[string]string{}       // authoritative (deciding-rule) names
	tentative := map[string]string{} // single-match log-mode names
	for _, row := range rows {
		f, err := decodeFlow(row)
		if err != nil || f == nil {
			continue
		}
		e := cfEdgeEvent(f)
		if e == nil || e.Verdict.RuleName == "" {
			continue
		}
		name := e.Verdict.RuleName
		if rid := e.Verdict.RuleID; rid != "" && want[rid] {
			if _, seen := out[rid]; !seen {
				out[rid] = name
			}
		}
		// A single matched rule is unambiguous: the description belongs to it.
		// Several matched rules share one description field, so associating it
		// with all of them would misname, and those are skipped.
		if matched := cfMatchedRuleIDs(e); len(matched) == 1 && want[matched[0]] {
			if _, seen := tentative[matched[0]]; !seen {
				tentative[matched[0]] = name
			}
		}
	}
	for id, name := range tentative {
		if _, decided := out[id]; !decided {
			out[id] = name
		}
	}
	return out, nil
}
