// Package jetstream provides the durable, replayable ingest buffer.
//
// Constitution Principle I is non-negotiable: every record must reach durable,
// replayable storage before any parsing happens. JetStream supplies exactly that
// with a single small binary — durable streams, replay from sequence, and
// consumer groups — without Kafka's operational weight (research.md R9).
package jetstream

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/menta2k/siem-v2/backend/internal/ingest"
	"github.com/nats-io/nats.go"
)

// Buffer implements ingest.Buffer over NATS JetStream.
type Buffer struct {
	conn     *nats.Conn
	js       nats.JetStreamContext
	subject  string
	stream   string
	maxBytes int64
}

// Stats is the buffer's current pressure. The meaningful pressure signal is the
// UN-CONSUMED backlog, not the byte fill: a Discard=old stream sits at its byte
// cap by design (it evicts the oldest, already-consumed message to make room),
// so bytes/cap is ~1 in healthy steady state and says nothing. What matters is
// how much of the buffered stream the consumer has NOT processed yet — once
// that is most of the stream, eviction starts dropping un-consumed data.
type Stats struct {
	Pending  int64 // messages delivered-unacked + not-yet-delivered
	Msgs     int64 // total messages currently in the stream
	Bytes    int64 // on-disk size of the stream
	MaxBytes int64 // configured byte cap (0 = unlimited)
	// BacklogFraction is Pending/Msgs — the share of the buffered stream still
	// un-consumed. This, not bytes/cap, is the "approaching data loss" signal.
	BacklogFraction float64
}

// Config configures the buffer.
type Config struct {
	URL        string
	StreamName string
	Subject    string
	MaxAge     time.Duration
	// MaxBytes caps the stream's on-disk size. With Discard=old, reaching it
	// evicts the OLDEST message (already consumed when the consumer is caught up)
	// rather than rejecting new publishes — a self-healing buffer, not an ingest
	// outage. A larger cap buys more headroom for the consumer to be briefly down
	// without un-consumed data reaching the eviction point. See the Discard note
	// in Connect for why Discard=new is the wrong lever here.
	MaxBytes int64
}

func DefaultConfig() Config {
	return Config{
		URL: nats.DefaultURL, StreamName: "SIEM_RAW",
		Subject: "siem.raw", MaxAge: 7 * 24 * time.Hour,
		MaxBytes: 20 << 30, // 20 GiB
	}
}

// Connect establishes the buffer and ensures the stream exists.
func Connect(cfg Config) (*Buffer, error) {
	if cfg.StreamName == "" {
		cfg = DefaultConfig()
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

	// FileStorage, not memory: the entire point of this component is surviving a
	// crash. A memory-backed stream would satisfy the interface and violate the
	// principle.
	streamCfg := &nats.StreamConfig{
		Name:      cfg.StreamName,
		Subjects:  []string{cfg.Subject + ".>"},
		Storage:   nats.FileStorage,
		Retention: nats.LimitsPolicy,
		MaxAge:    cfg.MaxAge,
		MaxBytes:  cfg.MaxBytes,
		// Discard=old is the RIGHT choice for this replay buffer, and Discard=new
		// is a trap here. Retention is LimitsPolicy: messages are kept for MaxAge
		// regardless of consumption, so with Discard=new a full stream would
		// reject new publishes until the backlog AGES OUT (7 days) — a permanent
		// ingest 503, the 2026-08-20 outage. With Discard=old a full stream evicts
		// the OLDEST message, which is already consumed whenever the consumer is
		// caught up — so healthy operation loses nothing. The loss window is only
		// un-consumed messages reaching the eviction point, i.e. the consumer
		// having fallen 20 GiB behind. The real defence against that is keeping
		// the consumer alive and caught up (see the supervised consumer in
		// cmd/logproc), not flipping the discard policy. Deeper protection is a
		// larger MaxBytes (more outage headroom) — not Discard=new, which needs
		// WorkQueue retention (immutable here, and it forfeits replay).
		Discard: nats.DiscardOld,
	}
	if _, err = js.AddStream(streamCfg); err != nil {
		if !isStreamExists(err) {
			conn.Close()
			return nil, fmt.Errorf("create stream %s: %w", cfg.StreamName, err)
		}
		// The stream predates this process. Reconcile its config so a cap added
		// after the stream was first created (e.g. MaxBytes) is actually applied,
		// rather than silently keeping the old unbounded config until someone
		// deletes the stream by hand.
		if _, err = js.UpdateStream(streamCfg); err != nil {
			conn.Close()
			return nil, fmt.Errorf("update stream %s: %w", cfg.StreamName, err)
		}
	}

	return &Buffer{
		conn: conn, js: js, subject: cfg.Subject,
		stream: cfg.StreamName, maxBytes: cfg.MaxBytes,
	}, nil
}

// Stats reports the buffer's backlog and fill level, for health/alerting. It is
// best-effort: on any query error it returns the zero Stats and the error, and
// the caller treats "unknown" as "do not raise a false alarm".
func (b *Buffer) Stats(durable string) (Stats, error) {
	si, err := b.js.StreamInfo(b.stream)
	if err != nil {
		return Stats{}, fmt.Errorf("stream info: %w", err)
	}
	s := Stats{Bytes: int64(si.State.Bytes), MaxBytes: b.maxBytes, Msgs: int64(si.State.Msgs)}
	if ci, err := b.js.ConsumerInfo(b.stream, durable); err == nil {
		s.Pending = int64(ci.NumPending) + int64(ci.NumAckPending)
	}
	if s.Msgs > 0 {
		s.BacklogFraction = float64(s.Pending) / float64(s.Msgs)
	}
	return s, nil
}

// maxMessageBytes bounds one JetStream message, comfortably under NATS's
// default 1 MiB max_payload.
//
// This limit is the reason Append CHUNKS: a real Logpush delivery can be up to
// 1 GB (max_upload_bytes), and publishing it as one message fails at the
// server whatever we negotiate — found the hard way when a burst test's every
// batch came back 503. Chunking keeps the durability guarantee independent of
// server tuning.
const maxMessageBytes = 512 * 1024

// Append durably persists a batch, returning only once JetStream has
// acknowledged every chunk. A receiver that acks its caller before this returns
// would lose the batch on a crash.
//
// Large batches are split so no single message exceeds maxMessageBytes. Each
// chunk carries a deterministic sub-id, so a retried publish after an ambiguous
// failure deduplicates chunk-by-chunk — the successfully published prefix is
// not re-appended.
func (b *Buffer) Append(ctx context.Context, batch ingest.RawBatch) error {
	subject := fmt.Sprintf("%s.%s", b.subject, batch.Provider)

	for chunkIndex, chunk := range splitBatch(batch, maxMessageBytes) {
		payload, err := json.Marshal(chunk)
		if err != nil {
			return fmt.Errorf("encode batch chunk: %w", err)
		}
		// MsgId makes publication idempotent within JetStream's dedup window.
		msgID := fmt.Sprintf("%s#%d", batch.BatchID, chunkIndex)
		if _, err := b.js.Publish(subject, payload, nats.MsgId(msgID), nats.Context(ctx)); err != nil {
			return fmt.Errorf("publish batch chunk %d to %s: %w", chunkIndex, subject, err)
		}
	}
	return nil
}

// splitBatch divides a batch into chunks whose serialized size stays under the
// limit. Record boundaries are never split: a record larger than the limit
// travels alone (the per-record cap in ingest.TruncateRecord keeps that case
// bounded well below NATS's ceiling).
func splitBatch(batch ingest.RawBatch, limit int) []ingest.RawBatch {
	if len(batch.Records) == 0 {
		return []ingest.RawBatch{batch}
	}

	// Fixed per-batch envelope overhead plus per-record base64 expansion (~4/3)
	// approximates the marshaled size without a trial marshal per chunk.
	const envelope = 512
	var chunks []ingest.RawBatch
	current := batch
	current.Records = nil
	size := envelope

	flush := func() {
		if len(current.Records) > 0 {
			chunks = append(chunks, current)
			next := batch
			next.Records = nil
			current = next
			size = envelope
		}
	}

	for _, rec := range batch.Records {
		recSize := len(rec)*4/3 + 8
		if size+recSize > limit {
			flush()
		}
		current.Records = append(current.Records, rec)
		size += recSize
	}
	flush()
	return chunks
}

// Consume delivers batches to fn. Acknowledgement happens only after fn returns
// nil, so a processing failure redelivers rather than silently dropping.
func (b *Buffer) Consume(ctx context.Context, durable string, fn func(context.Context, ingest.RawBatch) error) error {
	sub, err := b.js.PullSubscribe(b.subject+".>", durable, nats.AckExplicit())
	if err != nil {
		return fmt.Errorf("subscribe: %w", err)
	}
	defer sub.Unsubscribe()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		msgs, err := sub.Fetch(64, nats.MaxWait(2*time.Second))
		if err != nil {
			if err == nats.ErrTimeout {
				continue
			}
			return fmt.Errorf("fetch: %w", err)
		}
		for _, msg := range msgs {
			var batch ingest.RawBatch
			if err := json.Unmarshal(msg.Data, &batch); err != nil {
				// A batch we cannot even decode will never succeed on redelivery.
				// Terminate it so it stops cycling, rather than blocking the stream.
				_ = msg.Term()
				continue
			}
			if err := fn(ctx, batch); err != nil {
				_ = msg.Nak()
				continue
			}
			_ = msg.Ack()
		}
	}
}

// Close releases the connection.
func (b *Buffer) Close() {
	if b.conn != nil {
		b.conn.Close()
	}
}

// Ping reports whether the buffer is reachable.
func (b *Buffer) Ping() error {
	if b.conn == nil || !b.conn.IsConnected() {
		return fmt.Errorf("nats not connected")
	}
	return nil
}

func isStreamExists(err error) bool {
	return err != nil && (err == nats.ErrStreamNameAlreadyInUse ||
		contains(err.Error(), "already in use") || contains(err.Error(), "stream name already"))
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
