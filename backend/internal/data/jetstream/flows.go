package jetstream

import (
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
)

// FlowStream is the hand-off buffer between the collection tier and the
// analysis consumers that want completed flows (today: the traffic profiler).
//
// It is deliberately NOT a store of record — VictoriaLogs holds the flows.
// Short MaxAge and a small MaxBytes make it a bounded conveyor: a consumer
// that is down accumulates and replays within the window; one that is gone
// for longer loses only profile freshness, never flow data.
type FlowStream struct {
	conn    *nats.Conn
	js      nats.JetStreamContext
	subject string
}

// FlowStreamConfig configures the conveyor.
type FlowStreamConfig struct {
	URL        string
	StreamName string
	Subject    string
	MaxAge     time.Duration
	MaxBytes   int64
}

func DefaultFlowStreamConfig() FlowStreamConfig {
	return FlowStreamConfig{
		URL:        nats.DefaultURL,
		StreamName: "SIEM_FLOWS",
		Subject:    "siem.flows",
		MaxAge:     24 * time.Hour,
		MaxBytes:   2 << 30, // 2 GiB
	}
}

// ConnectFlows establishes the stream, mirroring Connect for the raw buffer.
func ConnectFlows(cfg FlowStreamConfig) (*FlowStream, error) {
	def := DefaultFlowStreamConfig()
	if cfg.URL == "" {
		cfg.URL = def.URL
	}
	if cfg.StreamName == "" {
		cfg.StreamName = def.StreamName
	}
	if cfg.Subject == "" {
		cfg.Subject = def.Subject
	}
	if cfg.MaxAge <= 0 {
		cfg.MaxAge = def.MaxAge
	}
	if cfg.MaxBytes <= 0 {
		cfg.MaxBytes = def.MaxBytes
	}

	conn, err := nats.Connect(cfg.URL,
		nats.MaxReconnects(-1),
		nats.ReconnectWait(time.Second),
	)
	if err != nil {
		return nil, fmt.Errorf("connect nats at %s: %w", cfg.URL, err)
	}
	js, err := conn.JetStream()
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("jetstream context: %w", err)
	}

	// Discard=old with a byte cap, like the raw buffer: a full conveyor drops
	// its oldest (least useful) flows rather than ever pushing back on the
	// store path. See the MaxBytes lesson in buffer.go.
	streamCfg := &nats.StreamConfig{
		Name:      cfg.StreamName,
		Subjects:  []string{cfg.Subject},
		Storage:   nats.FileStorage,
		Retention: nats.LimitsPolicy,
		MaxAge:    cfg.MaxAge,
		MaxBytes:  cfg.MaxBytes,
		Discard:   nats.DiscardOld,
	}
	if _, err = js.AddStream(streamCfg); err != nil {
		if !isStreamExists(err) {
			conn.Close()
			return nil, fmt.Errorf("create stream %s: %w", cfg.StreamName, err)
		}
		if _, err = js.UpdateStream(streamCfg); err != nil {
			conn.Close()
			return nil, fmt.Errorf("update stream %s: %w", cfg.StreamName, err)
		}
	}
	return &FlowStream{conn: conn, js: js, subject: cfg.Subject}, nil
}

// Publish appends one flow payload, returning once JetStream acknowledged it.
// Callers that must never block (the store path) run this on their own
// publisher goroutines behind a bounded queue.
func (s *FlowStream) Publish(payload []byte) error {
	_, err := s.js.Publish(s.subject, payload)
	return err
}

// PullSubscribe returns a durable pull subscription for a consumer that
// manages its own acknowledgement. The profiler acks only after the flush
// covering a message has committed, so AckWait must comfortably exceed its
// flush interval.
func (s *FlowStream) PullSubscribe(durable string, ackWait time.Duration) (*nats.Subscription, error) {
	if ackWait <= 0 {
		ackWait = 5 * time.Minute
	}
	sub, err := s.js.PullSubscribe(s.subject, durable,
		nats.AckExplicit(), nats.AckWait(ackWait))
	if err != nil {
		return nil, fmt.Errorf("subscribe %s: %w", s.subject, err)
	}
	return sub, nil
}

// Ping verifies the connection is alive.
func (s *FlowStream) Ping() error {
	if s.conn == nil || !s.conn.IsConnected() {
		return fmt.Errorf("nats connection down")
	}
	return nil
}

// Close releases the connection.
func (s *FlowStream) Close() {
	if s.conn != nil {
		s.conn.Close()
	}
}
