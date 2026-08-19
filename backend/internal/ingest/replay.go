package ingest

import (
	"context"
	"fmt"
	"time"
)

// ReplaySource supplies batches to be reprocessed.
//
// Replay exists because parsers have bugs and formats change. Constitution
// Principle II keeps the original bytes precisely so that a fix six weeks later
// is a reprocessing job rather than a permanent gap (FR-063).
type ReplaySource interface {
	// Batches returns raw batches in a time range for a provider.
	Batches(ctx context.Context, provider string, from, to time.Time) ([]RawBatch, error)
	// DeadLettered returns records that previously failed to parse.
	DeadLettered(ctx context.Context, provider string) ([]DeadLetterRecord, error)
	// MarkReprocessed records that a dead-lettered record was recovered.
	MarkReprocessed(ctx context.Context, dlID string) error
}

// Processor consumes a batch, as the live pipeline does.
type Processor interface {
	ProcessBatch(ctx context.Context, batch RawBatch) error
}

// Replayer reprocesses stored records.
type Replayer struct {
	Source    ReplaySource
	Processor Processor
	// DryRun reports what would be reprocessed without writing anything, so an
	// operator can size the job before committing to it.
	DryRun bool
}

// ReplayResult summarizes a run.
type ReplayResult struct {
	BatchesRead         int
	RecordsProcessed    int
	DeadLetterRecovered int
	Failures            []error
	DryRun              bool
}

// ReplayRange reprocesses a provider's batches over a time range.
func (r *Replayer) ReplayRange(ctx context.Context, provider string, from, to time.Time) (ReplayResult, error) {
	result := ReplayResult{DryRun: r.DryRun}
	if !to.After(from) {
		return result, fmt.Errorf("replay range must end after it starts")
	}

	batches, err := r.Source.Batches(ctx, provider, from, to)
	if err != nil {
		return result, fmt.Errorf("read batches for replay: %w", err)
	}

	for _, batch := range batches {
		result.BatchesRead++
		result.RecordsProcessed += len(batch.Records)
		if r.DryRun {
			continue
		}
		if err := r.Processor.ProcessBatch(ctx, batch); err != nil {
			// One bad batch must not abort the replay: the operator is usually
			// recovering from exactly the kind of problem that makes some records
			// unprocessable, and stopping would leave the rest unrecovered.
			result.Failures = append(result.Failures,
				fmt.Errorf("batch %s: %w", batch.BatchID, err))
		}
	}
	return result, nil
}

// ReplayDeadLetters reprocesses records that previously failed to parse.
//
// This is the payoff for keeping the originals: a corrected parser turns a pile
// of dead letters back into flows.
func (r *Replayer) ReplayDeadLetters(ctx context.Context, provider string) (ReplayResult, error) {
	result := ReplayResult{DryRun: r.DryRun}

	records, err := r.Source.DeadLettered(ctx, provider)
	if err != nil {
		return result, fmt.Errorf("read dead letters: %w", err)
	}

	for _, rec := range records {
		result.RecordsProcessed++
		if r.DryRun {
			continue
		}
		batch := RawBatch{
			BatchID:    "replay:" + rec.DLID,
			SourceID:   rec.SourceID,
			Tenant:     rec.Tenant,
			Provider:   rec.Provider,
			ReceivedAt: rec.ReceivedAt,
			Records:    [][]byte{rec.Payload},
		}
		if err := r.Processor.ProcessBatch(ctx, batch); err != nil {
			// Still failing means the parser fix did not cover this case. It stays
			// dead-lettered rather than being marked recovered, so the next attempt
			// finds it again.
			result.Failures = append(result.Failures, fmt.Errorf("record %s: %w", rec.DLID, err))
			continue
		}
		if err := r.Source.MarkReprocessed(ctx, rec.DLID); err != nil {
			result.Failures = append(result.Failures, fmt.Errorf("mark %s: %w", rec.DLID, err))
			continue
		}
		result.DeadLetterRecovered++
	}
	return result, nil
}
