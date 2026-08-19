// Package owasp evaluates captured requests against the OWASP Core Rule Set.
//
// This is replay, not protection: the requests here already happened and were
// already decided by a production WAF. The question being answered is "what
// would these rules do to this request", which imposes requirements inline
// protection does not — above all, that the same input and rule version always
// produce the same result (FR-033).
package owasp

import (
	"fmt"
	"sync"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
)

// Engine holds a configured Coraza WAF.
//
// A coraza.WAF is safe for concurrent use and expensive to build, so one Engine
// is shared across all evaluations. Transactions are per-goroutine and cheap.
type Engine struct {
	waf coraza.WAF

	// Versions are recorded on every run so a result stays interpretable after an
	// upgrade moves the ruleset underneath it (FR-073c).
	EngineVersion  string
	RulesetVersion string

	once sync.Once
}

// Config controls engine construction.
type Config struct {
	// ParanoiaLevel selects how aggressive CRS is (1-4). Higher levels add rules
	// and false positives in equal measure, which is why it is recorded per run.
	ParanoiaLevel int
	// InboundAnomalyThreshold is the score at which CRS would block.
	InboundAnomalyThreshold int
	// RequestBodyLimit should be at or above what production allowed, so a replay
	// sees the same bytes the real WAF saw.
	RequestBodyLimit int64
}

// DefaultConfig matches CRS's own recommended starting point.
func DefaultConfig() Config {
	return Config{ParanoiaLevel: 1, InboundAnomalyThreshold: 5, RequestBodyLimit: 13107200}
}

// NewEngine builds a CRS-loaded WAF.
func NewEngine(cfg Config) (*Engine, error) {
	if cfg.ParanoiaLevel < 1 || cfg.ParanoiaLevel > 4 {
		return nil, fmt.Errorf("paranoia level must be 1-4, got %d", cfg.ParanoiaLevel)
	}
	if cfg.InboundAnomalyThreshold <= 0 {
		return nil, fmt.Errorf("inbound anomaly threshold must be positive, got %d", cfg.InboundAnomalyThreshold)
	}

	waf, err := coraza.NewWAF(coraza.NewWAFConfig().
		WithRootFS(coreruleset.FS).
		WithDirectives(directives(cfg)))
	if err != nil {
		return nil, fmt.Errorf("build coraza WAF with CRS: %w", err)
	}

	return &Engine{
		waf:            waf,
		EngineVersion:  CorazaVersion,
		RulesetVersion: CRSVersion,
	}, nil
}

// Versions of the embedded components, pinned so an evaluation run records what
// actually produced it.
const (
	CorazaVersion = "coraza/v3.7.0"
	CRSVersion    = "crs/4.25.0"
)

// directives assembles the SecLang configuration for replay.
//
// The choices here are the difference between a useful answer and a misleading
// one, so each is deliberate:
//
//   - SecRuleEngine DetectionOnly: a transaction records only one interruption,
//     so stopping at the first disruptive action would hide most of the matched
//     rules. Detection-only keeps every rule running, and "would this have
//     blocked" is computed afterwards from the anomaly score.
//   - No @rbl, no @geoLookup: both consult data that changes between capture and
//     replay, which would break FR-033's determinism.
//   - No persistent collections: SESSION and IP state describe now, not the
//     moment the request happened.
func directives(cfg Config) string {
	return fmt.Sprintf(`
Include @coraza.conf-recommended
Include @crs-setup.conf.example
SecAction "id:900000,phase:1,pass,t:none,nolog,setvar:tx.blocking_paranoia_level=%d"
SecAction "id:900001,phase:1,pass,t:none,nolog,setvar:tx.paranoia_level=%d"
SecAction "id:900110,phase:1,pass,t:none,nolog,setvar:tx.inbound_anomaly_score_threshold=%d"
Include @owasp_crs/*.conf
SecRuleEngine DetectionOnly
SecRequestBodyAccess On
SecRequestBodyLimit %d
SecRequestBodyLimitAction ProcessPartial
`, cfg.ParanoiaLevel, cfg.ParanoiaLevel, cfg.InboundAnomalyThreshold, cfg.RequestBodyLimit)
}
