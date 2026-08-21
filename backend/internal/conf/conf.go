// Package conf holds service configuration loaded from YAML plus the environment.
//
// Secrets are never values in this struct tree: they are references resolved at
// startup through secrets.go, so a config file committed to the repository can
// never carry a credential (FR-057).
package conf

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the root configuration for every service. Each service reads the
// sections it needs and ignores the rest, so one file shape serves all three.
type Config struct {
	Service    Service    `yaml:"service"`
	Server     Server     `yaml:"server"`
	Storage    Storage    `yaml:"storage"`
	Ingest     Ingest     `yaml:"ingest"`
	Correlate  Correlate  `yaml:"correlate"`
	Evaluation Evaluation `yaml:"evaluation"`
	Profiler   Profiler   `yaml:"profiler"`
}

type Service struct {
	Name    string `yaml:"name"`
	Version string `yaml:"version"`
	Env     string `yaml:"env"`
}

type Server struct {
	HTTPAddr     string        `yaml:"http_addr"`
	GRPCAddr     string        `yaml:"grpc_addr"`
	ReadTimeout  time.Duration `yaml:"read_timeout"`
	WriteTimeout time.Duration `yaml:"write_timeout"`
}

type Storage struct {
	VictoriaLogs VictoriaLogs `yaml:"victorialogs"`
	Postgres     Postgres     `yaml:"postgres"`
	Valkey       Valkey       `yaml:"valkey"`
	JetStream    JetStream    `yaml:"jetstream"`
	ObjectStore  ObjectStore  `yaml:"objectstore"`
}

// VictoriaLogs is addressed per retention class, because retention is a
// per-instance flag and expiry is per-day-partition (research.md R7).
type VictoriaLogs struct {
	Hot  string `yaml:"hot"`
	Warm string `yaml:"warm"`
	// Raw addresses the dedicated instance holding unmodified provider records,
	// which carry a shorter, independently configurable retention. Empty means
	// co-locate raw with Hot (single-instance dev stacks).
	Raw string `yaml:"raw"`
	// Tenant headers are injected server-side only; clients never supply them (R8).
	AccountID uint32 `yaml:"account_id"`
	ProjectID uint32 `yaml:"project_id"`
}

type Postgres struct {
	DSNRef   string `yaml:"dsn_ref"`
	MaxConns int32  `yaml:"max_conns"`
	MinConns int32  `yaml:"min_conns"`
}

type Valkey struct {
	Addrs []string `yaml:"addrs"`
}

type JetStream struct {
	URL        string `yaml:"url"`
	StreamName string `yaml:"stream_name"`
	MaxAgeDays int    `yaml:"max_age_days"`
	// MaxBytesGiB caps the ingest buffer's on-disk size. It is a HARD safety:
	// without it the stream is bounded only by MaxAgeDays and can overrun the
	// JetStream file-store ceiling, at which point NATS rejects every publish and
	// all ingest 503s (a production outage, 2026-08-20). With Discard=old the cap
	// drops the oldest already-processed message instead of ever blocking ingest.
	MaxBytesGiB int `yaml:"max_bytes_gib"`
}

// ObjectStore is addressed through the S3 API only, so any S3-compatible store
// is a configuration swap rather than a code change (research.md R13).
type ObjectStore struct {
	Endpoint      string `yaml:"endpoint"`
	Region        string `yaml:"region"`
	ArchiveBucket string `yaml:"archive_bucket"`
	AuditBucket   string `yaml:"audit_bucket"`
	AccessKeyRef  string `yaml:"access_key_ref"`
	SecretKeyRef  string `yaml:"secret_key_ref"`
	UsePathStyle  bool   `yaml:"use_path_style"`
}

type Ingest struct {
	LogpushSecretRef string        `yaml:"logpush_secret_ref"`
	VectorSecretRef  string        `yaml:"vector_secret_ref"`
	MaxBodyBytes     int64         `yaml:"max_body_bytes"`
	PullInterval     time.Duration `yaml:"pull_interval"`
}

type Correlate struct {
	// LateArrivalWindow bounds how long a flow stays open waiting for records
	// that may never come (FR-019). Default 15m per the spec's assumptions.
	LateArrivalWindow time.Duration `yaml:"late_arrival_window"`
	// HeuristicWindow bounds time proximity for the fallback join (FR-072b).
	HeuristicWindow time.Duration `yaml:"heuristic_window"`
}

// Profiler configures the traffic profiler daemon (profilerd). Which domains
// are analyzed is PER-TENANT policy edited in the GUI and stored on the tenant
// row; this section only tunes the process itself.
type Profiler struct {
	// FlushInterval is how often learned profiles are committed to Postgres.
	// Consumed messages are acknowledged only after the covering flush, so a
	// crash replays at most one interval.
	FlushInterval time.Duration `yaml:"flush_interval"`
	// ConsumerName is the durable JetStream consumer identity on SIEM_FLOWS.
	ConsumerName string `yaml:"consumer_name"`
	// MaxPendingFlows forces an early flush once this many messages await
	// acknowledgement, bounding both memory and the replay window.
	MaxPendingFlows int `yaml:"max_pending_flows"`
}

type Evaluation struct {
	WirefilterURL    string        `yaml:"wirefilter_url"`
	Timeout          time.Duration `yaml:"timeout"`
	ParanoiaLevel    int           `yaml:"paranoia_level"`
	AnomalyThreshold int           `yaml:"anomaly_threshold"`
	RequestBodyLimit int64         `yaml:"request_body_limit"`
}

// Load reads and validates a configuration file. Validation is deliberate and
// fail-fast: a service that starts with a half-valid configuration produces
// confusing failures much later, usually under load.
func Load(path string) (*Config, error) {
	// The path is the operator's own --conf flag; reading it is the function's
	// purpose, not an injection surface.
	//nolint:gosec // G304: operator-supplied config path
	raw, err := os.ReadFile(path) //#nosec G304 -- operator-supplied --conf flag
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	cfg := Default()
	if err := yaml.Unmarshal(raw, cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config %s: %w", path, err)
	}
	return cfg, nil
}

// Default returns the baseline configuration. Defaults come from the spec's
// stated assumptions so that an unset field behaves as the spec describes.
func Default() *Config {
	return &Config{
		Server: Server{
			HTTPAddr:     ":8000",
			GRPCAddr:     ":9000",
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
		},
		Storage: Storage{
			Postgres:  Postgres{MaxConns: 20, MinConns: 2},
			JetStream: JetStream{StreamName: "siem-raw", MaxAgeDays: 7, MaxBytesGiB: 20},
		},
		Ingest: Ingest{
			MaxBodyBytes: 1 << 30, // Logpush max_upload_bytes tops out at 1GB (R4)
			PullInterval: time.Minute,
		},
		Correlate: Correlate{
			LateArrivalWindow: 15 * time.Minute,
			HeuristicWindow:   5 * time.Second,
		},
		Evaluation: Evaluation{
			Timeout:          10 * time.Second,
			ParanoiaLevel:    1,
			AnomalyThreshold: 5,
			RequestBodyLimit: 10 << 20,
		},
		Profiler: Profiler{
			FlushInterval:   30 * time.Second,
			ConsumerName:    "profiler",
			MaxPendingFlows: 5000,
		},
	}
}

// Validate rejects configurations that would fail confusingly at runtime.
func (c *Config) Validate() error {
	if c.Correlate.LateArrivalWindow <= 0 {
		return fmt.Errorf("correlate.late_arrival_window must be positive")
	}
	if c.Correlate.HeuristicWindow <= 0 {
		return fmt.Errorf("correlate.heuristic_window must be positive")
	}
	if c.Correlate.HeuristicWindow >= c.Correlate.LateArrivalWindow {
		return fmt.Errorf("correlate.heuristic_window (%s) must be shorter than late_arrival_window (%s): "+
			"a heuristic window wider than the flow lifetime would join unrelated requests",
			c.Correlate.HeuristicWindow, c.Correlate.LateArrivalWindow)
	}
	if c.Evaluation.ParanoiaLevel < 1 || c.Evaluation.ParanoiaLevel > 4 {
		return fmt.Errorf("evaluation.paranoia_level must be 1-4, got %d", c.Evaluation.ParanoiaLevel)
	}
	if c.Ingest.MaxBodyBytes <= 0 {
		return fmt.Errorf("ingest.max_body_bytes must be positive")
	}
	if c.Profiler.FlushInterval <= 0 {
		return fmt.Errorf("profiler.flush_interval must be positive")
	}
	if c.Profiler.MaxPendingFlows <= 0 {
		return fmt.Errorf("profiler.max_pending_flows must be positive")
	}
	return nil
}
