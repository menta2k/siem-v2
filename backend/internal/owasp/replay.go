package owasp

import (
	"context"
	"fmt"
	"time"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
)

// CapturedRequest is a request reconstructed from stored records.
type CapturedRequest struct {
	ClientIP    string
	ClientPort  int
	ServerIP    string
	ServerPort  int
	Method      string
	URI         string
	HTTPVersion string
	Headers     map[string]string
	Body        []byte

	// Completeness describes what the capture is missing. It is carried into the
	// result rather than checked and forgotten, because an evaluation over a
	// truncated or masked request can differ from the production verdict and the
	// operator must be told (FR-035).
	BodyTruncated bool
	MaskedFields  []string
}

// MatchedRule is one rule that fired.
type MatchedRule struct {
	RuleID   int      `json:"rule_id"`
	Message  string   `json:"message"`
	Data     string   `json:"data"`
	Severity string   `json:"severity"`
	Tags     []string `json:"tags,omitempty"`
	URI      string   `json:"uri,omitempty"`
}

// Result is the outcome of one replay.
type Result struct {
	MatchedRules    []MatchedRule `json:"matched_rules"`
	AnomalyScore    int           `json:"anomaly_score"`
	ScoreAvailable  bool          `json:"score_available"`
	Threshold       int           `json:"threshold"`
	WouldBlock      bool          `json:"would_block"`
	Interrupted     bool          `json:"interrupted"`
	InterruptRule   int           `json:"interrupt_rule,omitempty"`
	InterruptAction string        `json:"interrupt_action,omitempty"`

	EngineVersion  string `json:"engine_version"`
	RulesetVersion string `json:"ruleset_version"`
	ParanoiaLevel  int    `json:"paranoia_level"`

	// Warnings state why a result may not match production.
	Warnings []string      `json:"warnings,omitempty"`
	Duration time.Duration `json:"-"`
}

// Evaluate replays one captured request through the rule engine.
//
// The transaction is always closed: Coraza pools transactions and their body
// buffers, so a leaked transaction leaks memory for every request in a batch.
func (e *Engine) Evaluate(ctx context.Context, req CapturedRequest, cfg Config) (*Result, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	started := time.Now()

	tx := e.waf.NewTransaction()
	defer func() {
		tx.ProcessLogging()
		_ = tx.Close()
	}()

	if err := feed(tx, req); err != nil {
		return nil, err
	}

	result := &Result{
		Threshold:      cfg.InboundAnomalyThreshold,
		EngineVersion:  e.EngineVersion,
		RulesetVersion: e.RulesetVersion,
		ParanoiaLevel:  cfg.ParanoiaLevel,
	}

	for _, m := range tx.MatchedRules() {
		rule := m.Rule()
		result.MatchedRules = append(result.MatchedRules, MatchedRule{
			RuleID:   rule.ID(),
			Message:  m.Message(),
			Data:     m.Data(),
			Severity: rule.Severity().String(),
			Tags:     rule.Tags(),
			URI:      m.URI(),
		})
	}

	if it := tx.Interruption(); it != nil {
		result.Interrupted = true
		result.InterruptRule = it.RuleID
		result.InterruptAction = it.Action
	}

	// The anomaly score lives in a TX variable with no typed accessor; see
	// score.go for why this particular variable.
	if state, ok := tx.(plugintypes.TransactionState); ok {
		if score, found := anomalyScoreFrom(state); found {
			result.AnomalyScore = score
			result.ScoreAvailable = true
		}
	}

	// "Would block" is computed from the score rather than read from the
	// interruption, because DetectionOnly deliberately suppresses the disruptive
	// action that would otherwise have set it.
	result.WouldBlock = result.ScoreAvailable && result.AnomalyScore >= cfg.InboundAnomalyThreshold
	if !result.ScoreAvailable && result.Interrupted {
		// Fall back to the interruption if the score could not be read, so a
		// missing variable degrades rather than silently reporting "allowed".
		result.WouldBlock = true
		result.Warnings = append(result.Warnings,
			"anomaly score unavailable; would_block derived from the rule interruption instead")
	}

	result.Warnings = append(result.Warnings, completenessWarnings(req)...)
	result.Duration = time.Since(started)
	return result, nil
}

// feed drives the ModSecurity phases in order.
//
// Order is not stylistic: phase 2 rules never run unless ProcessRequestBody is
// called, so skipping it for a bodyless GET would silently under-report matches
// and make a replay disagree with production for reasons invisible in the output.
func feed(tx types.Transaction, req CapturedRequest) error {
	tx.ProcessConnection(req.ClientIP, req.ClientPort, req.ServerIP, req.ServerPort)

	version := req.HTTPVersion
	if version == "" {
		version = "HTTP/1.1"
	}
	tx.ProcessURI(req.URI, req.Method, version)

	for k, v := range req.Headers {
		tx.AddRequestHeader(k, v)
	}
	if host := req.Headers["Host"]; host != "" {
		tx.SetServerName(host)
	}

	tx.ProcessRequestHeaders()

	if len(req.Body) > 0 {
		if _, _, err := tx.WriteRequestBody(req.Body); err != nil {
			return fmt.Errorf("write request body: %w", err)
		}
	}
	if _, err := tx.ProcessRequestBody(); err != nil {
		return fmt.Errorf("process request body: %w", err)
	}
	return nil
}

// completenessWarnings states why a result might differ from production.
func completenessWarnings(req CapturedRequest) []string {
	var out []string
	if req.BodyTruncated {
		out = append(out, "the captured request body was truncated; "+
			"rules matching on the missing portion cannot fire, so this result may "+
			"differ from the production verdict")
	}
	if len(req.MaskedFields) > 0 {
		out = append(out, fmt.Sprintf("%d field(s) were masked before storage (%v); "+
			"rules inspecting them evaluate against the mask, not the original value",
			len(req.MaskedFields), req.MaskedFields))
	}
	if req.ClientIP == "" {
		out = append(out, "no client address in the capture; IP-based rules cannot evaluate correctly")
	}
	if len(req.Headers) == 0 {
		out = append(out, "no request headers in the capture; header-based rules cannot fire")
	}
	return out
}
