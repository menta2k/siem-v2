// Package ingest receives provider records and puts them beyond reach of loss
// before anything else happens to them.
package ingest

import (
	"context"
	"time"

	"github.com/menta2k/siem-v2/backend/internal/normalize/schema"
)

// RawBatch is a delivery as it arrived, before parsing.
type RawBatch struct {
	BatchID    string
	SourceID   string
	Tenant     string
	Provider   schema.Provider
	ReceivedAt time.Time
	// Records are the individual raw records, unmodified.
	Records [][]byte
}

// Buffer is the durable, replayable store that every record passes through
// before it is parsed.
//
// This interface exists to make Constitution Principle I structural rather than
// aspirational: a receiver cannot acknowledge a delivery without first calling
// Append and having it return successfully. Parsing happens downstream, reading
// from the buffer — never inline on the request path.
type Buffer interface {
	// Append durably persists a batch. It returns only once the batch will
	// survive a crash; a receiver that acks before this returns loses data.
	Append(ctx context.Context, batch RawBatch) error
}

// Deduper decides whether a record has already been seen.
//
// Every provider in this system delivers at-least-once, so duplicates are
// routine rather than exceptional. Deduplication is keyed on the record's
// deterministic id so redelivery collapses to a single occurrence in flows,
// counts and alert evidence (FR-007).
type Deduper interface {
	// Seen reports whether the id was already recorded, and records it if not.
	// The bool is true when the record is NEW and should be processed.
	Seen(ctx context.Context, id string) (isNew bool, err error)
}

// MemoryBuffer is an in-memory Buffer for tests and local development.
//
// It is deliberately NOT durable, and says so, because a buffer that silently
// fails to persist would defeat the one guarantee this interface exists to
// provide.
type MemoryBuffer struct {
	Batches []RawBatch
}

func (m *MemoryBuffer) Append(_ context.Context, batch RawBatch) error {
	m.Batches = append(m.Batches, batch)
	return nil
}

// RecordCount reports how many individual records the buffer holds.
func (m *MemoryBuffer) RecordCount() int {
	n := 0
	for _, b := range m.Batches {
		n += len(b.Records)
	}
	return n
}

// MemoryDeduper is an in-memory Deduper for tests.
type MemoryDeduper struct {
	seen map[string]bool
}

func NewMemoryDeduper() *MemoryDeduper {
	return &MemoryDeduper{seen: map[string]bool{}}
}

func (m *MemoryDeduper) Seen(_ context.Context, id string) (bool, error) {
	if m.seen == nil {
		m.seen = map[string]bool{}
	}
	if m.seen[id] {
		return false, nil
	}
	m.seen[id] = true
	return true, nil
}
