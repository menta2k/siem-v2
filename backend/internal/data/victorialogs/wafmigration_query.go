package victorialogs

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/menta2k/siem-v2/backend/internal/biz/flow"
)

// WAF-migration read queries over correlated flows. The stages compare, per
// request, what F5 blocked vs what Cloudflare did, using the index fields added
// in wafmigration_index.go. Multi-value fields (f5_violations, cf_matched_rules)
// cannot be stats-by-exploded in LogsQL, so those aggregations fetch the
// (bounded) matching flows and group in Go.

// scanCap bounds how many flows a stage scan fetches before it aggregates in Go.
// F5 blocks and log-mode rule matches are both rare, so this is generous.
const wafScanCap = 100000

// WafUncoveredGroup is one F5 violation on one host+method that Cloudflare let
// through — the unit a single new Cloudflare rule would be written for.
type WafUncoveredGroup struct {
	Violation             string    `json:"violation"`
	RequestHost           string    `json:"request_host"`
	RequestMethod         string    `json:"request_method"`
	Requests              int       `json:"requests"`
	Paths                 int       `json:"paths"`
	Clients               int       `json:"clients"`
	CloudflareAllowlisted int       `json:"cloudflare_allowlisted"`
	FirstSeen             time.Time `json:"first_seen"`
	LastSeen              time.Time `json:"last_seen"`
}

// WafRuleCounts is the raw F5-agreement tally for one Cloudflare rule; the
// service turns it into a reading.
type WafRuleCounts struct {
	RuleID     string
	RuleName   string
	Correlated int
	F5Blocked  int
	F5Flagged  int
	F5Allowed  int
	Hosts      map[string]bool
	FirstSeen  time.Time
	LastSeen   time.Time
}

func wafTimeWindow(from, to time.Time) string {
	return fmt.Sprintf("_time:[%s, %s]", from.UTC().Format(time.RFC3339), to.UTC().Format(time.RFC3339))
}

func wafHostClause(host string) (string, error) {
	if host == "" {
		return "", nil
	}
	if !safeValue.MatchString(host) {
		return "", &ErrUnsafeValue{Field: "host", Value: host}
	}
	return " host:=" + quote(host), nil
}

// WafLogModeRule is one Cloudflare rule running in log/monitor mode and how
// often it matched over the window — the "what are my log-mode rules doing"
// overview, independent of any F5 agreement.
type WafLogModeRule struct {
	RuleID    string    `json:"rule_id"`
	RuleName  string    `json:"rule_name,omitempty"`
	Matches   int       `json:"matches"`
	Hosts     int       `json:"hosts"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// WafLogModeRules counts, per Cloudflare rule, how many log-mode (monitored)
// requests it matched. Rule ids are exploded from cf_matched_rules over the
// (bounded) monitored flows and aggregated in Go, since multi-value fields
// cannot be stats-by-exploded in LogsQL. Names are resolved by the caller.
func (r *FlowRepo) WafLogModeRules(ctx context.Context, tenant, host string, from, to time.Time) ([]WafLogModeRule, bool, error) {
	if !safeValue.MatchString(tenant) || tenant == "" {
		return nil, false, &ErrUnsafeValue{Field: "tenant", Value: tenant}
	}
	hostClause, err := wafHostClause(host)
	if err != nil {
		return nil, false, err
	}
	q := fmt.Sprintf(`{tenant=%s,record_kind=%s} %s cf_verdict:=monitored cf_matched_rules:*%s `+
		`| fields host, cf_matched_rules, _time`,
		quote(tenant), quote(string(KindFlow)), wafTimeWindow(from, to), hostClause)
	rows, err := r.client.Query(ctx, r.tenant, q, wafScanCap+1)
	if err != nil {
		return nil, false, err
	}
	truncated := len(rows) > wafScanCap
	if truncated {
		rows = rows[:wafScanCap]
	}

	type agg struct {
		rule  WafLogModeRule
		hosts map[string]bool
	}
	byRule := map[string]*agg{}
	for _, row := range rows {
		hostV, _ := row["host"].(string)
		matched, _ := row["cf_matched_rules"].(string)
		ts := parseVLTime(row["_time"])
		for _, rid := range strings.Fields(matched) {
			a := byRule[rid]
			if a == nil {
				a = &agg{rule: WafLogModeRule{RuleID: rid, FirstSeen: ts, LastSeen: ts}, hosts: map[string]bool{}}
				byRule[rid] = a
			}
			a.rule.Matches++
			if hostV != "" {
				a.hosts[hostV] = true
			}
			if !ts.IsZero() {
				if a.rule.FirstSeen.IsZero() || ts.Before(a.rule.FirstSeen) {
					a.rule.FirstSeen = ts
				}
				if ts.After(a.rule.LastSeen) {
					a.rule.LastSeen = ts
				}
			}
		}
	}
	out := make([]WafLogModeRule, 0, len(byRule))
	for _, a := range byRule {
		a.rule.Hosts = len(a.hosts)
		out = append(out, a.rule)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Matches != out[j].Matches {
			return out[i].Matches > out[j].Matches
		}
		return out[i].RuleID < out[j].RuleID
	})
	return out, truncated, nil
}

// WafUncovered returns the coverage gaps: flows F5 blocked and Cloudflare
// allowed, grouped by (F5 violation, host, method).
func (r *FlowRepo) WafUncovered(ctx context.Context, tenant, host string, from, to time.Time) ([]WafUncoveredGroup, bool, error) {
	if !safeValue.MatchString(tenant) || tenant == "" {
		return nil, false, &ErrUnsafeValue{Field: "tenant", Value: tenant}
	}
	hostClause, err := wafHostClause(host)
	if err != nil {
		return nil, false, err
	}
	q := fmt.Sprintf(`{tenant=%s,record_kind=%s} %s f5_verdict:=blocked cf_verdict:=allowed%s `+
		`| fields host, method, path, client_ip, f5_violations, cf_matched_rules, _time`,
		quote(tenant), quote(string(KindFlow)), wafTimeWindow(from, to), hostClause)
	rows, err := r.client.Query(ctx, r.tenant, q, wafScanCap+1)
	if err != nil {
		return nil, false, err
	}
	truncated := len(rows) > wafScanCap
	if truncated {
		rows = rows[:wafScanCap]
	}

	type agg struct {
		g       WafUncoveredGroup
		paths   map[string]bool
		clients map[string]bool
	}
	groups := map[string]*agg{}
	for _, row := range rows {
		hostV, _ := row["host"].(string)
		method, _ := row["method"].(string)
		path, _ := row["path"].(string)
		clientIP, _ := row["client_ip"].(string)
		violations, _ := row["f5_violations"].(string)
		matched, _ := row["cf_matched_rules"].(string)
		ts := parseVLTime(row["_time"])
		for _, viol := range strings.Fields(violations) {
			key := viol + "\x1f" + hostV + "\x1f" + method
			a := groups[key]
			if a == nil {
				a = &agg{
					g:     WafUncoveredGroup{Violation: viol, RequestHost: hostV, RequestMethod: method, FirstSeen: ts, LastSeen: ts},
					paths: map[string]bool{}, clients: map[string]bool{},
				}
				groups[key] = a
			}
			a.g.Requests++
			if path != "" {
				a.paths[path] = true
			}
			if clientIP != "" {
				a.clients[clientIP] = true
			}
			if matched != "" {
				a.g.CloudflareAllowlisted++
			}
			if !ts.IsZero() {
				if a.g.FirstSeen.IsZero() || ts.Before(a.g.FirstSeen) {
					a.g.FirstSeen = ts
				}
				if ts.After(a.g.LastSeen) {
					a.g.LastSeen = ts
				}
			}
		}
	}
	out := make([]WafUncoveredGroup, 0, len(groups))
	for _, a := range groups {
		a.g.Paths = len(a.paths)
		a.g.Clients = len(a.clients)
		out = append(out, a.g)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Requests != out[j].Requests {
			return out[i].Requests > out[j].Requests
		}
		return out[i].Violation < out[j].Violation
	})
	return out, truncated, nil
}

// wafMaxCandidates caps how many distinct log-mode rules a run considers.
const wafMaxCandidates = 200

// WafCandidateRules returns the Cloudflare rule ids observed matching a request
// in monitor/log mode — the migration candidates, derivable from data alone.
//
// A log-mode match does NOT populate the deciding `rule_id` (Cloudflare only
// sets that for an enforced action); the matched rule appears only in the
// multi-value `cf_matched_rules`. So candidates are the distinct rule ids
// exploded from cf_matched_rules over the (rare, bounded) monitored flows,
// ranked by frequency — not a `stats by (rule_id)`, which would find nothing.
func (r *FlowRepo) WafCandidateRules(ctx context.Context, tenant, host string, from, to time.Time) ([]string, error) {
	if !safeValue.MatchString(tenant) || tenant == "" {
		return nil, &ErrUnsafeValue{Field: "tenant", Value: tenant}
	}
	hostClause, err := wafHostClause(host)
	if err != nil {
		return nil, err
	}
	q := fmt.Sprintf(`{tenant=%s,record_kind=%s} %s cf_verdict:=monitored cf_matched_rules:*%s `+
		`| fields cf_matched_rules`,
		quote(tenant), quote(string(KindFlow)), wafTimeWindow(from, to), hostClause)
	rows, err := r.client.Query(ctx, r.tenant, q, wafScanCap)
	if err != nil {
		return nil, err
	}
	counts := map[string]int{}
	for _, row := range rows {
		matched, _ := row["cf_matched_rules"].(string)
		for _, rid := range strings.Fields(matched) {
			if safeValue.MatchString(rid) {
				counts[rid]++
			}
		}
	}
	out := make([]string, 0, len(counts))
	for id := range counts {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool {
		if counts[out[i]] != counts[out[j]] {
			return counts[out[i]] > counts[out[j]]
		}
		return out[i] < out[j]
	})
	if len(out) > wafMaxCandidates {
		out = out[:wafMaxCandidates]
	}
	return out, nil
}

// WafAgreement tallies, for each candidate rule, how F5 decided the requests
// that rule matched. One fetch (flows touching any candidate rule, with both
// vendors reporting), aggregated per-rule in Go.
func (r *FlowRepo) WafAgreement(ctx context.Context, tenant, host string, ruleIDs []string, from, to time.Time) ([]WafRuleCounts, bool, error) {
	if !safeValue.MatchString(tenant) || tenant == "" {
		return nil, false, &ErrUnsafeValue{Field: "tenant", Value: tenant}
	}
	if len(ruleIDs) == 0 {
		return nil, false, nil
	}
	candidate := map[string]bool{}
	terms := make([]string, 0, len(ruleIDs))
	for _, id := range ruleIDs {
		if !safeValue.MatchString(id) {
			continue
		}
		candidate[id] = true
		terms = append(terms, "cf_matched_rules:"+quote(id))
	}
	hostClause, err := wafHostClause(host)
	if err != nil {
		return nil, false, err
	}
	q := fmt.Sprintf(`{tenant=%s,record_kind=%s} %s f5_verdict:* cf_verdict:* (%s)%s `+
		`| fields host, f5_verdict, cf_matched_rules, rule_name, _time`,
		quote(tenant), quote(string(KindFlow)), wafTimeWindow(from, to), strings.Join(terms, " OR "), hostClause)
	rows, err := r.client.Query(ctx, r.tenant, q, wafScanCap+1)
	if err != nil {
		return nil, false, err
	}
	truncated := len(rows) > wafScanCap
	if truncated {
		rows = rows[:wafScanCap]
	}

	byRule := map[string]*WafRuleCounts{}
	for _, row := range rows {
		hostV, _ := row["host"].(string)
		f5v, _ := row["f5_verdict"].(string)
		matched, _ := row["cf_matched_rules"].(string)
		ruleName, _ := row["rule_name"].(string)
		ts := parseVLTime(row["_time"])
		for _, rid := range strings.Fields(matched) {
			if !candidate[rid] {
				continue
			}
			c := byRule[rid]
			if c == nil {
				c = &WafRuleCounts{RuleID: rid, Hosts: map[string]bool{}, FirstSeen: ts, LastSeen: ts}
				byRule[rid] = c
			}
			// A log-mode match's rule name is only present when Cloudflare ships
			// a SecurityRuleDescription; often empty on this deployment, so the
			// console degrades to the bare id. First non-empty wins.
			if c.RuleName == "" && ruleName != "" {
				c.RuleName = ruleName
			}
			c.Correlated++
			switch f5v {
			case "blocked":
				c.F5Blocked++
			case "monitored":
				c.F5Flagged++
			case "allowed":
				c.F5Allowed++
			}
			if hostV != "" {
				c.Hosts[hostV] = true
			}
			if !ts.IsZero() {
				if c.FirstSeen.IsZero() || ts.Before(c.FirstSeen) {
					c.FirstSeen = ts
				}
				if ts.After(c.LastSeen) {
					c.LastSeen = ts
				}
			}
		}
	}
	out := make([]WafRuleCounts, 0, len(byRule))
	for _, c := range byRule {
		out = append(out, *c)
	}
	return out, truncated, nil
}

// WafSelector picks a group's sample requests.
type WafSelector struct {
	Violation, RuleID, RequestHost, RequestMethod, F5Verdict, CloudflareVerdict string
}

// WafSamples returns example flows for a selector, newest first.
func (r *FlowRepo) WafSamples(ctx context.Context, tenant string, sel WafSelector, from, to time.Time, limit int) ([]*flow.Flow, error) {
	if !safeValue.MatchString(tenant) || tenant == "" {
		return nil, &ErrUnsafeValue{Field: "tenant", Value: tenant}
	}
	var clauses []string
	add := func(field, val string) error {
		if val == "" {
			return nil
		}
		if !safeValue.MatchString(val) {
			return &ErrUnsafeValue{Field: field, Value: val}
		}
		clauses = append(clauses, field+":"+quote(val))
		return nil
	}
	// Multi-value word-match for the group key; exact for the scalar filters.
	for _, kv := range []struct{ f, v string }{
		{"f5_violations", sel.Violation}, {"cf_matched_rules", sel.RuleID},
	} {
		if err := add(kv.f, kv.v); err != nil {
			return nil, err
		}
	}
	for _, kv := range []struct{ f, v string }{
		{"host:=", sel.RequestHost}, {"method:=", sel.RequestMethod},
		{"f5_verdict:=", sel.F5Verdict}, {"cf_verdict:=", sel.CloudflareVerdict},
	} {
		if kv.v == "" {
			continue
		}
		if !safeValue.MatchString(kv.v) {
			return nil, &ErrUnsafeValue{Field: kv.f, Value: kv.v}
		}
		clauses = append(clauses, kv.f+quote(kv.v))
	}
	if limit <= 0 || limit > 50 {
		limit = 20
	}
	q := fmt.Sprintf(`{tenant=%s,record_kind=%s} %s %s | sort by (_time desc) | limit %d`,
		quote(tenant), quote(string(KindFlow)), wafTimeWindow(from, to), strings.Join(clauses, " "), limit)
	rows, err := r.client.Query(ctx, r.tenant, q, limit)
	if err != nil {
		return nil, err
	}
	out := make([]*flow.Flow, 0, len(rows))
	seen := map[string]bool{}
	for _, row := range rows {
		f, err := decodeFlow(row)
		if err != nil || f == nil || seen[f.FlowID] {
			continue
		}
		seen[f.FlowID] = true
		out = append(out, f)
	}
	return out, nil
}

func parseVLTime(v any) time.Time {
	s, _ := v.(string)
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t
}
