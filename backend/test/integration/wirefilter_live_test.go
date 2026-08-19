//go:build integration

package integration

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/menta2k/siem-v2/backend/internal/cfrules"
)

func TestWirefilterSidecarLive(t *testing.T) {
	url := os.Getenv("SIEM_TEST_WIREFILTER_URL")
	if url == "" {
		url = "http://localhost:18084"
	}
	c := cfrules.New(url, 5*time.Second)
	if err := c.Health(context.Background()); err != nil {
		t.Skipf("sidecar not running: %v", err)
	}

	resp, err := c.Evaluate(context.Background(),
		`http.request.uri.path contains "/admin" and ip.src in {203.0.113.0/24}`,
		[]cfrules.CapturedRequest{
			{Ref: "match", Fields: cfrules.FieldsFromFlow("GET", "shop.example.com", "/admin/login", "", "", "203.0.113.9")},
			{Ref: "nomatch", Fields: cfrules.FieldsFromFlow("GET", "shop.example.com", "/products", "", "", "203.0.113.9")},
		})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if !resp.ExpressionValid {
		t.Fatalf("expression should parse: %s", resp.ParseError)
	}
	if len(resp.Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(resp.Results))
	}
	for _, r := range resp.Results {
		want := r.Ref == "match"
		if r.Matched != want {
			t.Errorf("%s: matched=%v, want %v", r.Ref, r.Matched, want)
		}
		if len(r.Caveats) != 0 {
			t.Errorf("%s: a complete capture should produce no caveats, got %v", r.Ref, r.Caveats)
		}
	}
	t.Logf("live sidecar: scheme=%s engine=%s", resp.SchemeVersion, resp.EngineVersion)
}
