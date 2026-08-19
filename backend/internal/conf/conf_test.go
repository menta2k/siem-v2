package conf

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{"defaults are valid", func(*Config) {}, ""},
		{
			"heuristic window wider than flow lifetime is rejected",
			func(c *Config) {
				c.Correlate.HeuristicWindow = 30 * time.Minute
				c.Correlate.LateArrivalWindow = 15 * time.Minute
			},
			"must be shorter than late_arrival_window",
		},
		{
			"paranoia level out of range",
			func(c *Config) { c.Evaluation.ParanoiaLevel = 5 },
			"paranoia_level must be 1-4",
		},
		{
			"zero late arrival window",
			func(c *Config) { c.Correlate.LateArrivalWindow = 0 },
			"late_arrival_window must be positive",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := Default()
			tt.mutate(c)
			err := c.Validate()
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("expected valid, got %v", err)
			case tt.wantErr != "" && err == nil:
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			case tt.wantErr != "" && !strings.Contains(err.Error(), tt.wantErr):
				t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestEnvResolverRejectsLiteralSecrets(t *testing.T) {
	r := EnvResolver{}
	if _, err := r.Resolve("hunter2"); err == nil {
		t.Fatal("a literal secret value must be rejected, not treated as a reference")
	}
	t.Setenv("SIEM_TEST_SECRET", "value")
	got, err := r.Resolve("env:SIEM_TEST_SECRET")
	if err != nil || got != "value" {
		t.Fatalf("resolve env ref: got %q, %v", got, err)
	}
	if _, err := r.Resolve("env:SIEM_TEST_MISSING"); err == nil {
		t.Fatal("missing secret must fail fast at startup, not at first use")
	}
}

func TestLoadFromFile(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/conf.yaml"
	body := []byte(`
service:
  name: test
server:
  http_addr: ":9999"
correlate:
  late_arrival_window: 10m
  heuristic_window: 2s
evaluation:
  paranoia_level: 2
`)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Server.HTTPAddr != ":9999" {
		t.Errorf("addr: got %q", cfg.Server.HTTPAddr)
	}
	if cfg.Correlate.LateArrivalWindow != 10*time.Minute {
		t.Errorf("window: got %v", cfg.Correlate.LateArrivalWindow)
	}
	// Unset fields keep their defaults rather than becoming zero.
	if cfg.Ingest.MaxBodyBytes == 0 {
		t.Error("an unset field must retain its default, not become zero")
	}
	if cfg.Evaluation.ParanoiaLevel != 2 {
		t.Errorf("paranoia level: got %d", cfg.Evaluation.ParanoiaLevel)
	}
}

func TestLoadRejectsMissingAndMalformed(t *testing.T) {
	if _, err := Load("/nonexistent/conf.yaml"); err == nil {
		t.Error("a missing config must fail at startup, not at first use")
	}
	dir := t.TempDir()
	bad := dir + "/bad.yaml"
	if err := os.WriteFile(bad, []byte("server: [this is not a map]"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(bad); err == nil {
		t.Error("malformed YAML must be rejected")
	}
}

func TestLoadRejectsInvalidValues(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/invalid.yaml"
	if err := os.WriteFile(path, []byte("evaluation:\n  paranoia_level: 9\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Error("validation must run on load, not be deferred to runtime")
	}
}
