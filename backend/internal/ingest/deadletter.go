package ingest

import (
	"context"
	"time"

	"github.com/menta2k/siem-v2/backend/internal/normalize/schema"
)

// DeadLetterRecord is a record that could not be normalized.
//
// It keeps the ORIGINAL bytes, not a partially-parsed remnant. A parser bug
// found six weeks later is only recoverable if the input survived intact, which
// is why FR-012 forbids discarding these and why reprocessing is a first-class
// operation rather than a manual salvage job.
type DeadLetterRecord struct {
	DLID           string
	RawID          string
	SourceID       string
	Tenant         string
	Provider       schema.Provider
	Payload        []byte
	FailureReason  string
	ParserVersion  string
	ReceivedAt     time.Time
	ReprocessState ReprocessState
}

type ReprocessState string

const (
	ReprocessPending     ReprocessState = "pending"
	ReprocessReprocessed ReprocessState = "reprocessed"
	ReprocessAbandoned   ReprocessState = "abandoned"
)

// DeadLetter stores records that failed to parse.
type DeadLetter interface {
	Put(ctx context.Context, rec DeadLetterRecord) error
}

// MemoryDeadLetter is an in-memory DeadLetter for tests.
type MemoryDeadLetter struct {
	Records []DeadLetterRecord
}

func (m *MemoryDeadLetter) Put(_ context.Context, rec DeadLetterRecord) error {
	m.Records = append(m.Records, rec)
	return nil
}
