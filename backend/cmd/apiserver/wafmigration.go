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

// wafRuleAgreement is one Cloudflare rule's agreement row on the wire.
type wafRuleAgreement struct {
	RuleID      string    `json:"rule_id"`
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
			RuleID: c.RuleID, Correlated: c.Correlated,
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
	sortWafRules(rules)
	writeJSON(w, http.StatusOK, map[string]any{
		"rules": rules, "min_correlated": wafMinCorrelated, "truncated": truncated,
	})
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
	FlowID            string   `json:"flow_id"`
	EventTime         string   `json:"event_time"`
	ClientIP          string   `json:"client_ip"`
	Country           string   `json:"country"`
	RequestHost       string   `json:"request_host"`
	RequestPath       string   `json:"request_path"`
	RequestQuery      string   `json:"request_query"`
	RequestMethod     string   `json:"request_method"`
	UserAgent         string   `json:"user_agent"`
	F5Verdict         string   `json:"f5_verdict"`
	F5Violations      []string `json:"f5_violations"`
	CloudflareVerdict string   `json:"cloudflare_verdict"`
	CloudflareRuleID  string   `json:"cloudflare_rule_id"`
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
	writeJSON(w, http.StatusOK, map[string]any{"samples": samples})
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
		FlowID: f.FlowID, ClientIP: f.Client.IP, Country: f.Client.Country,
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
			}
		}
	}
	return sm
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

func (s *apiServer) wafErr(w http.ResponseWriter, err error) {
	var unsafe *victorialogs.ErrUnsafeValue
	if errors.As(err, &unsafe) {
		writeError(w, apierrors.InvalidInput("A filter value is not valid.", err.Error()))
		return
	}
	writeError(w, apierrors.Internal(err.Error()))
}
