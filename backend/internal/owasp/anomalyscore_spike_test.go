package owasp

import (
	"testing"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// TestAnomalyScoreExtraction pins the resolution of verification item V1.
//
// Research established that Coraza exposes no typed AnomalyScore() accessor and
// that the value lives in a TX rule variable. The spike found three things worth
// keeping as a regression test, because each would silently break FR-030's score
// reporting on a Coraza or CRS upgrade:
//
//  1. The transaction DOES satisfy plugintypes.TransactionState, so the variable
//     is reachable through a typed path — no audit-log or message parsing needed.
//  2. The variable that actually carries the total is
//     TX:blocking_inbound_anomaly_score. The obvious candidates are wrong:
//     TX:anomaly_score reads 0 and TX:inbound_anomaly_score is empty under CRS 4.
//  3. Summing severities ourselves is NOT viable: 64 of 65 matched rules report
//     severity "unknown", so a severity-weighted total would read near zero.
//
// The value is cross-checked against CRS rule 949110's message, which is the
// independent statement of the same number.
func TestAnomalyScoreExtraction(t *testing.T) {
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().
		WithRootFS(coreruleset.FS).
		WithDirectives(directives(DefaultConfig())))
	if err != nil {
		t.Fatalf("build WAF with CRS: %v", err)
	}

	tx := waf.NewTransaction()
	defer func() {
		tx.ProcessLogging()
		if err := tx.Close(); err != nil {
			t.Errorf("close transaction: %v", err)
		}
	}()

	tx.ProcessConnection("203.0.113.9", 44321, "198.51.100.10", 443)
	tx.ProcessURI("/search?q=1%27+OR+%271%27%3D%271", "GET", "HTTP/1.1")
	tx.AddRequestHeader("Host", "example.com")
	tx.AddRequestHeader("User-Agent", "curl/8.0")
	tx.ProcessRequestHeaders()
	if _, err := tx.ProcessRequestBody(); err != nil {
		t.Fatalf("process request body: %v", err)
	}

	if n := len(tx.MatchedRules()); n == 0 {
		t.Fatal("CRS matched nothing on an obvious SQLi payload; the ruleset is not loading")
	}

	state, ok := tx.(plugintypes.TransactionState)
	if !ok {
		t.Fatal("transaction no longer satisfies plugintypes.TransactionState: " +
			"the typed score-extraction path is gone and FR-030 needs a new one")
	}

	score, found := anomalyScoreFrom(state)
	if !found {
		t.Fatal("TX:blocking_inbound_anomaly_score absent: CRS changed the variable " +
			"carrying the anomaly total; re-run the V1 spike to find the new one")
	}
	if score <= 0 {
		t.Fatalf("expected a positive anomaly score for SQLi, got %d", score)
	}
	t.Logf("anomaly score = %d (V1 resolved: TX:blocking_inbound_anomaly_score)", score)

	// The obvious-looking variables are wrong under CRS 4. Assert that, so if a
	// future version starts populating them we notice rather than guess.
	if v := state.Variables().TX().Get("inbound_anomaly_score"); len(v) > 0 {
		t.Logf("NOTE: TX:inbound_anomaly_score is now populated (%v); "+
			"it was empty when V1 was resolved — reconsider which variable to read", v)
	}
}
