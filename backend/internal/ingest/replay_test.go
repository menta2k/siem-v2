package ingest

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakeSource struct {
	batches     []RawBatch
	deadLetters []DeadLetterRecord
	marked      []string
}

func (f *fakeSource) Batches(context.Context, string, time.Time, time.Time) ([]RawBatch, error) {
	return f.batches, nil
}
func (f *fakeSource) DeadLettered(context.Context, string) ([]DeadLetterRecord, error) {
	return f.deadLetters, nil
}
func (f *fakeSource) MarkReprocessed(_ context.Context, id string) error {
	f.marked = append(f.marked, id)
	return nil
}

type fakeProcessor struct {
	seen   []RawBatch
	failOn string
}

func (f *fakeProcessor) ProcessBatch(_ context.Context, b RawBatch) error {
	if f.failOn != "" && b.BatchID == f.failOn {
		return errors.New("still unparseable")
	}
	f.seen = append(f.seen, b)
	return nil
}

var rbase = time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)

func TestReplayRangeReprocesses(t *testing.T) {
	src := &fakeSource{batches: []RawBatch{
		{BatchID: "b1", Records: [][]byte{[]byte("a"), []byte("b")}},
		{BatchID: "b2", Records: [][]byte{[]byte("c")}},
	}}
	proc := &fakeProcessor{}
	r := &Replayer{Source: src, Processor: proc}

	res, err := r.ReplayRange(context.Background(), "cloudflare", rbase, rbase.Add(time.Hour))
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if res.BatchesRead != 2 || res.RecordsProcessed != 3 {
		t.Fatalf("unexpected result: %+v", res)
	}
	if len(proc.seen) != 2 {
		t.Errorf("both batches should be reprocessed, got %d", len(proc.seen))
	}
}

// TestDryRunWritesNothing lets an operator size the job before committing.
func TestDryRunWritesNothing(t *testing.T) {
	src := &fakeSource{batches: []RawBatch{{BatchID: "b1", Records: [][]byte{[]byte("a")}}}}
	proc := &fakeProcessor{}
	r := &Replayer{Source: src, Processor: proc, DryRun: true}

	res, err := r.ReplayRange(context.Background(), "cloudflare", rbase, rbase.Add(time.Hour))
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if res.RecordsProcessed != 1 {
		t.Errorf("a dry run should still report what it would do, got %+v", res)
	}
	if len(proc.seen) != 0 {
		t.Fatal("a dry run must not write anything")
	}
}

// TestDeadLetterRecoveryIsThePayoff: keeping the original bytes turns a parser
// fix into a recovery rather than a permanent gap.
func TestDeadLetterRecovery(t *testing.T) {
	src := &fakeSource{deadLetters: []DeadLetterRecord{
		{DLID: "dl1", Provider: "nginx", Payload: []byte("recoverable line")},
		{DLID: "dl2", Provider: "nginx", Payload: []byte("also recoverable")},
	}}
	proc := &fakeProcessor{}
	r := &Replayer{Source: src, Processor: proc}

	res, err := r.ReplayDeadLetters(context.Background(), "nginx")
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if res.DeadLetterRecovered != 2 {
		t.Fatalf("expected both records recovered, got %+v", res)
	}
	if len(src.marked) != 2 {
		t.Error("recovered records must be marked so they are not reprocessed forever")
	}
}

// TestStillFailingRecordStaysDeadLettered: if the parser fix did not cover this
// case, the record must remain findable rather than be marked recovered.
func TestStillFailingRecordStaysDeadLettered(t *testing.T) {
	src := &fakeSource{deadLetters: []DeadLetterRecord{
		{DLID: "dl1", Provider: "nginx", Payload: []byte("good")},
		{DLID: "dl2", Provider: "nginx", Payload: []byte("still bad")},
	}}
	proc := &fakeProcessor{failOn: "replay:dl2"}
	r := &Replayer{Source: src, Processor: proc}

	res, err := r.ReplayDeadLetters(context.Background(), "nginx")
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if res.DeadLetterRecovered != 1 {
		t.Errorf("only the parseable record should be recovered, got %d", res.DeadLetterRecovered)
	}
	if len(res.Failures) != 1 {
		t.Errorf("the still-failing record must be reported, got %v", res.Failures)
	}
	for _, id := range src.marked {
		if id == "dl2" {
			t.Fatal("a record that still fails must NOT be marked reprocessed")
		}
	}
}

// TestOneBadBatchDoesNotAbortTheReplay: the operator is usually recovering from
// exactly the problem that makes some records unprocessable.
func TestOneBadBatchDoesNotAbortTheReplay(t *testing.T) {
	src := &fakeSource{batches: []RawBatch{
		{BatchID: "b1", Records: [][]byte{[]byte("a")}},
		{BatchID: "bad", Records: [][]byte{[]byte("x")}},
		{BatchID: "b3", Records: [][]byte{[]byte("c")}},
	}}
	proc := &fakeProcessor{failOn: "bad"}
	r := &Replayer{Source: src, Processor: proc}

	res, err := r.ReplayRange(context.Background(), "cloudflare", rbase, rbase.Add(time.Hour))
	if err != nil {
		t.Fatalf("replay should not abort: %v", err)
	}
	if len(proc.seen) != 2 {
		t.Errorf("the good batches must still be processed, got %d", len(proc.seen))
	}
	if len(res.Failures) != 1 {
		t.Errorf("the failure must be reported, got %v", res.Failures)
	}
}

func TestInvalidRangeRejected(t *testing.T) {
	r := &Replayer{Source: &fakeSource{}, Processor: &fakeProcessor{}}
	if _, err := r.ReplayRange(context.Background(), "cloudflare", rbase, rbase.Add(-time.Hour)); err == nil {
		t.Fatal("a backwards range must be rejected")
	}
}
