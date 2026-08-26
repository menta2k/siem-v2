package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/menta2k/siem-v2/backend/internal/biz/flow"
	"github.com/menta2k/siem-v2/backend/internal/cfrules"
	"github.com/menta2k/siem-v2/backend/internal/data/victorialogs"
	apierrors "github.com/menta2k/siem-v2/backend/internal/errors"
	"github.com/menta2k/siem-v2/backend/internal/normalize/schema"
	"github.com/menta2k/siem-v2/backend/internal/owasp"
)

// WAF-migration read endpoints (F5 ASM -> Cloudflare). Evidence only: they say
// what a Cloudflare rule must catch and whether it agrees with F5, never write a
// rule. See internal/data/victorialogs/wafmigration_query.go for the queries.

// wafMinCorrelated is the evidence floor below which a rule's agreement is "not
// yet decided" — mirrors v1's MinCorrelatedForReading.
const wafMinCorrelated = 10

// wafWindow reads the ?hours= window (default one week, clamped 1..2160).
func wafWindow(r *http.Request) (from, to time.Time) {
	hours := 168
	if h, err := strconv.Atoi(r.URL.Query().Get("hours")); err == nil && h > 0 {
		hours = h
	}
	if hours > 2160 {
		hours = 2160
	}
	to = time.Now().UTC()
	return to.Add(-time.Duration(hours) * time.Hour), to
}

func (s *apiServer) wafUncovered(w http.ResponseWriter, r *http.Request) {
	from, to := wafWindow(r)
	groups, truncated, err := s.repo.WafUncovered(r.Context(), tenantOf(r), r.URL.Query().Get("host"), from, to)
	if err != nil {
		s.wafErr(w, err)
		return
	}
	if groups == nil {
		groups = []victorialogs.WafUncoveredGroup{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"groups": groups, "truncated": truncated})
}

// wafLogMode lists the Cloudflare rules running in log/monitor mode and how
// many times each matched over the window — the activity overview for a
// deployment whose rules are mostly still logging.
func (s *apiServer) wafLogMode(w http.ResponseWriter, r *http.Request) {
	from, to := wafWindow(r)
	rules, truncated, err := s.repo.WafLogModeRules(r.Context(), tenantOf(r), r.URL.Query().Get("host"), from, to)
	if err != nil {
		s.wafErr(w, err)
		return
	}
	if s.ruleNames != nil && len(rules) > 0 {
		ids := make([]string, 0, len(rules))
		for i := range rules {
			ids = append(ids, rules[i].RuleID)
		}
		names := s.ruleNames.Describe(r.Context(), tenantOf(r), ids)
		for i := range rules {
			if rules[i].RuleName == "" {
				rules[i].RuleName = names[rules[i].RuleID]
			}
		}
	}
	if rules == nil {
		rules = []victorialogs.WafLogModeRule{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": rules, "truncated": truncated})
}

// wafRuleAgreement is one Cloudflare rule's agreement row on the wire.
type wafRuleAgreement struct {
	RuleID      string    `json:"rule_id"`
	RuleName    string    `json:"rule_name,omitempty"`
	Correlated  int       `json:"correlated"`
	F5Blocked   int       `json:"f5_blocked"`
	F5Flagged   int       `json:"f5_flagged"`
	F5Allowed   int       `json:"f5_allowed"`
	Hosts       int       `json:"hosts"`
	RequestHost string    `json:"request_host"`
	Reading     string    `json:"reading"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
}

// wafReading classifies a rule by weighted F5 agreement (a flagged request
// counts half). Mirrors v1's thresholds.
func wafReading(c victorialogs.WafRuleCounts) string {
	if c.Correlated < wafMinCorrelated {
		return "insufficient"
	}
	ratio := (float64(c.F5Blocked) + float64(c.F5Flagged)/2) / float64(c.Correlated)
	switch {
	case ratio >= 0.8:
		return "ready"
	case ratio <= 0.2:
		return "false_positive"
	default:
		return "disputed"
	}
}

func (s *apiServer) wafRuleStage(w http.ResponseWriter, r *http.Request, keep map[string]bool) {
	from, to := wafWindow(r)
	host := r.URL.Query().Get("host")
	candidates, err := s.repo.WafCandidateRules(r.Context(), tenantOf(r), host, from, to)
	if err != nil {
		s.wafErr(w, err)
		return
	}
	counts, truncated, err := s.repo.WafAgreement(r.Context(), tenantOf(r), host, candidates, from, to)
	if err != nil {
		s.wafErr(w, err)
		return
	}
	rules := make([]wafRuleAgreement, 0, len(counts))
	for _, c := range counts {
		reading := wafReading(c)
		if !keep[reading] {
			continue
		}
		row := wafRuleAgreement{
			RuleID: c.RuleID, RuleName: c.RuleName, Correlated: c.Correlated,
			F5Blocked: c.F5Blocked, F5Flagged: c.F5Flagged, F5Allowed: c.F5Allowed,
			Hosts: len(c.Hosts), Reading: reading, FirstSeen: c.FirstSeen, LastSeen: c.LastSeen,
		}
		if len(c.Hosts) == 1 {
			for h := range c.Hosts {
				row.RequestHost = h
			}
		}
		rules = append(rules, row)
	}
	s.nameWafRules(r, rules)
	sortWafRules(rules)
	writeJSON(w, http.StatusOK, map[string]any{
		"rules": rules, "min_correlated": wafMinCorrelated, "truncated": truncated,
	})
}

// nameWafRules fills the rule name on any row that lacks one, resolving the ids
// in a single lookup. The counts query names a rule only when a flow it matched
// carried the description; this reaches names carried on other flows too.
func (s *apiServer) nameWafRules(r *http.Request, rules []wafRuleAgreement) {
	if s.ruleNames == nil {
		return
	}
	ids := make([]string, 0, len(rules))
	for i := range rules {
		if rules[i].RuleName == "" {
			ids = append(ids, rules[i].RuleID)
		}
	}
	if len(ids) == 0 {
		return
	}
	names := s.ruleNames.Describe(r.Context(), tenantOf(r), ids)
	for i := range rules {
		if rules[i].RuleName == "" {
			rules[i].RuleName = names[rules[i].RuleID]
		}
	}
}

func sortWafRules(rules []wafRuleAgreement) {
	// correlated desc, then id — deterministic under replay
	for i := 1; i < len(rules); i++ {
		for j := i; j > 0 && (rules[j].Correlated > rules[j-1].Correlated ||
			(rules[j].Correlated == rules[j-1].Correlated && rules[j].RuleID < rules[j-1].RuleID)); j-- {
			rules[j], rules[j-1] = rules[j-1], rules[j]
		}
	}
}

func (s *apiServer) wafReadyToEnforce(w http.ResponseWriter, r *http.Request) {
	s.wafRuleStage(w, r, map[string]bool{"ready": true, "disputed": true, "insufficient": true})
}

func (s *apiServer) wafFalsePositives(w http.ResponseWriter, r *http.Request) {
	s.wafRuleStage(w, r, map[string]bool{"false_positive": true})
}

func wafSelectorFromQuery(r *http.Request) victorialogs.WafSelector {
	q := r.URL.Query()
	return victorialogs.WafSelector{
		Violation: q.Get("violation"), RuleID: q.Get("rule_id"),
		RequestHost: q.Get("host"), RequestMethod: q.Get("method"),
		F5Verdict: q.Get("f5_verdict"), CloudflareVerdict: q.Get("cf_verdict"),
	}
}

// wafSample is one example request on the wire.
type wafSample struct {
	FlowID             string   `json:"flow_id"`
	EventTime          string   `json:"event_time"`
	ClientIP           string   `json:"client_ip"`
	ClientASN          int      `json:"client_asn,omitempty"`
	Country            string   `json:"country"`
	RequestHost        string   `json:"request_host"`
	RequestPath        string   `json:"request_path"`
	RequestQuery       string   `json:"request_query"`
	RequestMethod      string   `json:"request_method"`
	UserAgent          string   `json:"user_agent"`
	F5Verdict          string   `json:"f5_verdict"`
	F5Violations       []string `json:"f5_violations"`
	CloudflareVerdict  string   `json:"cloudflare_verdict"`
	CloudflareRuleID   string   `json:"cloudflare_rule_id"`
	CloudflareRuleName string   `json:"cloudflare_rule_name,omitempty"`
	// Cloudflare WAF attack scores, INVERTED (1 = attack, 100 = clean). Nil when
	// the Logpush job on this deployment does not ship them. -1 marks "not
	// scored" only for the overall score; the drivers are omitted when absent.
	AttackScore *int `json:"attack_score,omitempty"`
	SQLiScore   *int `json:"sqli_score,omitempty"`
	XSSScore    *int `json:"xss_score,omitempty"`
	RCEScore    *int `json:"rce_score,omitempty"`
}

func (s *apiServer) wafSamples(w http.ResponseWriter, r *http.Request) {
	from, to := wafWindow(r)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	flows, err := s.repo.WafSamples(r.Context(), tenantOf(r), wafSelectorFromQuery(r), from, to, limit)
	if err != nil {
		s.wafErr(w, err)
		return
	}
	samples := make([]wafSample, 0, len(flows))
	for _, f := range flows {
		samples = append(samples, wafSampleFromFlow(f))
	}
	s.nameWafSamples(r, samples)
	writeJSON(w, http.StatusOK, map[string]any{"samples": samples})
}

// nameWafSamples fills the Cloudflare rule name on samples that carry only an id.
func (s *apiServer) nameWafSamples(r *http.Request, samples []wafSample) {
	if s.ruleNames == nil {
		return
	}
	ids := make([]string, 0, len(samples))
	for i := range samples {
		if samples[i].CloudflareRuleName == "" && samples[i].CloudflareRuleID != "" {
			ids = append(ids, samples[i].CloudflareRuleID)
		}
	}
	if len(ids) == 0 {
		return
	}
	names := s.ruleNames.Describe(r.Context(), tenantOf(r), ids)
	for i := range samples {
		if samples[i].CloudflareRuleName == "" {
			samples[i].CloudflareRuleName = names[samples[i].CloudflareRuleID]
		}
	}
}

// wafVendorVerdict maps a normalized action to the three-word migration vocab.
func wafVendorVerdict(a schema.Action) string {
	switch a {
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

func wafSampleFromFlow(f *flow.Flow) wafSample {
	sm := wafSample{
		FlowID: f.FlowID, ClientIP: f.Client.IP, ClientASN: f.Client.ASN, Country: f.Client.Country,
		RequestHost: f.Request.Host, RequestPath: f.Request.Path, RequestMethod: f.Request.Method,
		UserAgent: f.Client.UserAgent, RequestQuery: f.Request.Query,
	}
	if !f.LastSeen.IsZero() {
		sm.EventTime = f.LastSeen.UTC().Format(time.RFC3339)
	}
	for i := range f.Events {
		e := &f.Events[i]
		switch {
		case e.Provider == schema.ProviderF5ASM:
			sm.F5Verdict = wafVendorVerdict(e.Verdict.Action)
			if v, _ := e.Verdict.ReasonRaw["violations"].(string); v != "" && v != "N/A" {
				for _, part := range strings.Split(v, ",") {
					if t := strings.TrimSpace(part); t != "" {
						sm.F5Violations = append(sm.F5Violations, t)
					}
				}
			}
		case e.Provider == schema.ProviderCloudflare && e.Layer == schema.LayerEdge:
			if sm.CloudflareVerdict == "" || e.Verdict.Action != schema.ActionAllowed {
				sm.CloudflareVerdict = wafVendorVerdict(e.Verdict.Action)
				sm.CloudflareRuleID = e.Verdict.RuleID
				sm.CloudflareRuleName = e.Verdict.RuleName
			}
			// Attack scores ride on the edge verdict's reason (any action), on
			// the INVERTED 1..100 scale. Absent on deployments whose Logpush job
			// omits them, in which case these stay nil.
			if sm.AttackScore == nil {
				sm.AttackScore = wafReasonInt(e.Verdict.ReasonRaw, "WAFAttackScore")
				sm.SQLiScore = wafReasonInt(e.Verdict.ReasonRaw, "WAFSQLiAttackScore")
				sm.XSSScore = wafReasonInt(e.Verdict.ReasonRaw, "WAFXSSAttackScore")
				sm.RCEScore = wafReasonInt(e.Verdict.ReasonRaw, "WAFRCEAttackScore")
			}
		}
	}
	return sm
}

// wafReasonInt reads an integer that survived JSON round-tripping (numbers
// decode to float64) from a verdict reason map. Returns nil when absent, so the
// console can tell "not scored" from "scored zero".
func wafReasonInt(reason map[string]any, key string) *int {
	if reason == nil {
		return nil
	}
	switch v := reason[key].(type) {
	case float64:
		n := int(v)
		return &n
	case int:
		return &v
	default:
		return nil
	}
}

// wafEvaluate tests a candidate Cloudflare expression against a group's real
// captured requests, reusing the wirefilter evaluator and the raw store.
func (s *apiServer) wafEvaluate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Hours      int                      `json:"hours"`
		Expression string                   `json:"expression"`
		Selector   victorialogs.WafSelector `json:"selector"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeError(w, apierrors.InvalidInput("The request body could not be read.", err.Error()))
		return
	}
	if strings.TrimSpace(req.Expression) == "" {
		writeError(w, apierrors.InvalidInput("An expression is required.", "empty expression"))
		return
	}
	if !s.cfRules.Configured() {
		writeError(w, apierrors.Unavailable(
			"Cloudflare expression evaluation is not configured on this deployment.", ""))
		return
	}
	hours := req.Hours
	if hours <= 0 {
		hours = 168
	}
	to := time.Now().UTC()
	from := to.Add(-time.Duration(hours) * time.Hour)
	flows, err := s.repo.WafSamples(r.Context(), tenantOf(r), req.Selector, from, to, 20)
	if err != nil {
		s.wafErr(w, err)
		return
	}
	reqs := make([]cfrules.CapturedRequest, 0, len(flows))
	for _, f := range flows {
		reqs = append(reqs, cfrules.CapturedRequest{
			Ref: f.FlowID,
			Fields: cfrules.FieldsFromFlow(f.Request.Method, f.Request.Host, f.Request.Path,
				f.Request.Query, f.Client.UserAgent, f.Client.IP),
		})
	}
	if len(reqs) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{
			"tested": 0, "matched": 0, "outcomes": []any{},
			"note": "No sample requests are retained for this group in the window.",
		})
		return
	}
	resp, err := s.cfRules.Evaluate(r.Context(), req.Expression, reqs)
	if err != nil {
		if err == cfrules.ErrNotConfigured {
			writeError(w, apierrors.Unavailable("Cloudflare expression evaluation is not configured.", err.Error()))
			return
		}
		writeError(w, apierrors.Internal(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// wafOwasp explains WHY a request trips the WAF: it replays one sample flow's
// request through the OWASP Core Rule Set and returns the rules that fired, each
// rule's score contribution, and the anomaly score against the block threshold.
// Cloudflare's managed OWASP ruleset reports only "949110: anomaly score
// exceeded" and never which rules built the score — this recovers them, since
// the managed ruleset IS the Core Rule Set.
func (s *apiServer) wafOwasp(w http.ResponseWriter, r *http.Request) {
	var req struct {
		FlowID        string `json:"flow_id"`
		ParanoiaLevel int    `json:"paranoia_level"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeError(w, apierrors.InvalidInput("The request body could not be read.", err.Error()))
		return
	}
	if strings.TrimSpace(req.FlowID) == "" {
		writeError(w, apierrors.InvalidInput("A flow id is required.", "empty flow_id"))
		return
	}
	f, err := s.repo.Get(r.Context(), tenantOf(r), req.FlowID)
	if err != nil {
		s.wafErr(w, err)
		return
	}
	if f == nil {
		writeError(w, apierrors.NotFound("flow not present for this tenant"))
		return
	}
	cfg := s.owaspCfg
	if req.ParanoiaLevel > 0 {
		cfg.ParanoiaLevel = req.ParanoiaLevel
	}
	captured, note := owaspRequestFromFlow(f)
	result, err := s.engine.Evaluate(r.Context(), captured, cfg)
	if err != nil {
		writeError(w, apierrors.Internal(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"result":              result,
		"engine":              s.engine.EngineVersion,
		"ruleset":             s.engine.RulesetVersion,
		"reconstruction_note": note,
	})
}

// owaspRequestFromFlow rebuilds the request for CRS replay from a correlated
// flow: method, URI and host/user-agent headers from the denormalized request,
// plus F5's captured form body where present. It is not the raw wire request —
// header-dependent rules may read differently — so it returns a note saying so.
func owaspRequestFromFlow(f *flow.Flow) (owasp.CapturedRequest, string) {
	uri := f.Request.Path
	if f.Request.Query != "" {
		uri += "?" + f.Request.Query
	}
	headers := map[string]string{}
	if f.Request.Host != "" {
		headers["Host"] = f.Request.Host
	}
	if f.Client.UserAgent != "" {
		headers["User-Agent"] = f.Client.UserAgent
	}
	var body []byte
	for i := range f.Events {
		e := &f.Events[i]
		if e.Shape != nil && e.Shape.BodyForm != "" {
			body = []byte(e.Shape.BodyForm)
			headers["Content-Type"] = "application/x-www-form-urlencoded"
			break
		}
	}
	note := "Replayed against the request reconstructed from the correlated flow — method, URI, host and user-agent, plus F5's captured form body where present. Rules that read headers absent from the capture may differ from the edge."
	if f.HasFlag(schema.FlagBodyTruncated) {
		note += " The captured body was truncated, so body rules that did not fire are not conclusive."
	}
	return owasp.CapturedRequest{
		ClientIP:      f.Client.IP,
		Method:        f.Request.Method,
		URI:           uri,
		Headers:       headers,
		Body:          body,
		BodyTruncated: f.HasFlag(schema.FlagBodyTruncated),
	}, note
}

func (s *apiServer) wafErr(w http.ResponseWriter, err error) {
	var unsafe *victorialogs.ErrUnsafeValue
	if errors.As(err, &unsafe) {
		writeError(w, apierrors.InvalidInput("A filter value is not valid.", err.Error()))
		return
	}
	writeError(w, apierrors.Internal(err.Error()))
}
