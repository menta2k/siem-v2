package owasp

import (
	"context"
	"testing"
)

func engine(t *testing.T) (*Engine, Config) {
	t.Helper()
	cfg := DefaultConfig()
	e, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("build engine: %v", err)
	}
	return e, cfg
}

func sqli() CapturedRequest {
	return CapturedRequest{
		ClientIP: "203.0.113.9", ClientPort: 44321,
		ServerIP: "198.51.100.10", ServerPort: 443,
		Method: "GET", URI: "/search?q=1%27+OR+%271%27%3D%271", HTTPVersion: "HTTP/1.1",
		Headers: map[string]string{"Host": "shop.example.com", "User-Agent": "curl/8.0"},
	}
}

func benign() CapturedRequest {
	return CapturedRequest{
		ClientIP: "198.51.100.42", ClientPort: 51234,
		ServerIP: "198.51.100.10", ServerPort: 443,
		Method: "GET", URI: "/products/12345", HTTPVersion: "HTTP/1.1",
		Headers: map[string]string{
			"Host":       "shop.example.com",
			"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
			"Accept":     "text/html,application/xhtml+xml",
		},
	}
}

// TestAllMatchedRulesReported is FR-030's core requirement. A transaction records
// only one interruption, so reporting that alone would hide most of what fired.
func TestAllMatchedRulesReported(t *testing.T) {
	e, cfg := engine(t)
	res, err := e.Evaluate(context.Background(), sqli(), cfg)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}

	if len(res.MatchedRules) < 2 {
		t.Fatalf("expected many matched rules for SQLi, got %d", len(res.MatchedRules))
	}
	if !res.ScoreAvailable {
		t.Fatal("the anomaly score must be readable; see V1 in research.md")
	}
	if res.AnomalyScore <= 0 {
		t.Errorf("SQLi should score above zero, got %d", res.AnomalyScore)
	}
	if !res.WouldBlock {
		t.Errorf("score %d against threshold %d should block", res.AnomalyScore, res.Threshold)
	}
	if res.EngineVersion == "" || res.RulesetVersion == "" {
		t.Error("versions must be recorded so the result stays interpretable after an upgrade")
	}
}

func TestBenignRequestDoesNotBlock(t *testing.T) {
	e, cfg := engine(t)
	res, err := e.Evaluate(context.Background(), benign(), cfg)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if res.WouldBlock {
		t.Errorf("an ordinary product page must not block: score=%d rules=%d",
			res.AnomalyScore, len(res.MatchedRules))
	}
}

// TestDeterminism is FR-033 and SC-015. Ten identical runs, identical results.
func TestDeterminism(t *testing.T) {
	e, cfg := engine(t)
	first, err := e.Evaluate(context.Background(), sqli(), cfg)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	for i := 0; i < 9; i++ {
		got, err := e.Evaluate(context.Background(), sqli(), cfg)
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		if got.AnomalyScore != first.AnomalyScore {
			t.Fatalf("run %d scored %d, first run scored %d", i, got.AnomalyScore, first.AnomalyScore)
		}
		if len(got.MatchedRules) != len(first.MatchedRules) {
			t.Fatalf("run %d matched %d rules, first matched %d",
				i, len(got.MatchedRules), len(first.MatchedRules))
		}
		if got.WouldBlock != first.WouldBlock {
			t.Fatalf("run %d disagreed on would_block", i)
		}
	}
}

// TestParanoiaLevelChangesOutcome proves the level is actually wired through
// rather than merely recorded.
func TestParanoiaLevelChangesOutcome(t *testing.T) {
	low := DefaultConfig()
	low.ParanoiaLevel = 1
	e1, err := NewEngine(low)
	if err != nil {
		t.Fatalf("pl1 engine: %v", err)
	}
	high := DefaultConfig()
	high.ParanoiaLevel = 4
	e4, err := NewEngine(high)
	if err != nil {
		t.Fatalf("pl4 engine: %v", err)
	}

	r1, err := e1.Evaluate(context.Background(), benign(), low)
	if err != nil {
		t.Fatalf("pl1 evaluate: %v", err)
	}
	r4, err := e4.Evaluate(context.Background(), benign(), high)
	if err != nil {
		t.Fatalf("pl4 evaluate: %v", err)
	}

	if r4.AnomalyScore < r1.AnomalyScore {
		t.Errorf("a higher paranoia level should not score lower: pl1=%d pl4=%d",
			r1.AnomalyScore, r4.AnomalyScore)
	}
	if r1.ParanoiaLevel != 1 || r4.ParanoiaLevel != 4 {
		t.Error("the level in force must be recorded on the result")
	}
}

// TestIncompleteCaptureWarns is FR-035: never let an operator read a result from
// partial input as if it were the production verdict.
func TestIncompleteCaptureWarns(t *testing.T) {
	e, cfg := engine(t)

	req := sqli()
	req.BodyTruncated = true
	req.MaskedFields = []string{"request.headers.authorization"}

	res, err := e.Evaluate(context.Background(), req, cfg)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if len(res.Warnings) < 2 {
		t.Fatalf("truncation and masking must each warn, got %v", res.Warnings)
	}

	clean, err := e.Evaluate(context.Background(), sqli(), cfg)
	if err != nil {
		t.Fatalf("evaluate clean: %v", err)
	}
	if len(clean.Warnings) != 0 {
		t.Errorf("a complete capture should warn about nothing, got %v", clean.Warnings)
	}
}

func TestMissingClientIPWarns(t *testing.T) {
	e, cfg := engine(t)
	req := sqli()
	req.ClientIP = ""
	res, err := e.Evaluate(context.Background(), req, cfg)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	found := false
	for _, w := range res.Warnings {
		if contains(w, "client address") {
			found = true
		}
	}
	if !found {
		t.Errorf("a capture without a client address must warn; IP rules cannot evaluate: %v", res.Warnings)
	}
}

// TestBodyIsInspected confirms phase 2 actually runs. If ProcessRequestBody were
// skipped, body rules would never fire and replays would silently under-report.
func TestBodyIsInspected(t *testing.T) {
	e, cfg := engine(t)
	req := CapturedRequest{
		ClientIP: "203.0.113.9", ClientPort: 1234, ServerIP: "198.51.100.10", ServerPort: 443,
		Method: "POST", URI: "/login", HTTPVersion: "HTTP/1.1",
		Headers: map[string]string{
			"Host":         "shop.example.com",
			"Content-Type": "application/x-www-form-urlencoded",
		},
		Body: []byte("username=admin&password=' OR '1'='1"),
	}
	res, err := e.Evaluate(context.Background(), req, cfg)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if len(res.MatchedRules) == 0 {
		t.Fatal("an SQLi payload in the body must match rules; if not, phase 2 never ran")
	}
}

func TestCancelledContextIsRespected(t *testing.T) {
	e, cfg := engine(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.Evaluate(ctx, sqli(), cfg); err == nil {
		t.Fatal("a cancelled context must abort before doing work")
	}
}

func TestInvalidConfigRejected(t *testing.T) {
	for _, cfg := range []Config{
		{ParanoiaLevel: 0, InboundAnomalyThreshold: 5},
		{ParanoiaLevel: 5, InboundAnomalyThreshold: 5},
		{ParanoiaLevel: 1, InboundAnomalyThreshold: 0},
	} {
		if _, err := NewEngine(cfg); err == nil {
			t.Errorf("config %+v should be rejected at construction, not misbehave at runtime", cfg)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
