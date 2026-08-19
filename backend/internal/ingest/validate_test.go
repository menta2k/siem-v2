package ingest

import (
	"context"
	"strings"
	"testing"
)

func TestAuthenticateSecret(t *testing.T) {
	if !AuthenticateSecret("token", "token") {
		t.Error("matching secrets must authenticate")
	}
	if AuthenticateSecret("token", "other") {
		t.Error("mismatched secrets must not authenticate")
	}
	// An unset expected secret means the deployment is misconfigured. Failing
	// open would leave the ingest endpoint silently unauthenticated.
	if AuthenticateSecret("anything", "") {
		t.Error("an empty expected secret must never authenticate")
	}
	if AuthenticateSecret("", "") {
		t.Error("empty against empty must still fail closed")
	}
}

func TestBearerToken(t *testing.T) {
	cases := map[string]string{
		"Bearer abc123": "abc123",
		"bearer abc123": "abc123",
		"BEARER abc123": "abc123",
		"abc123":        "abc123",
		"  abc123  ":    "abc123",
		"":              "",
	}
	for in, want := range cases {
		if got := BearerToken(in); got != want {
			t.Errorf("BearerToken(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestValidateBatchSize(t *testing.T) {
	if err := ValidateBatchSize(100, 1000); err != nil {
		t.Errorf("within limit should pass: %v", err)
	}
	if err := ValidateBatchSize(2000, 1000); err == nil {
		t.Error("over limit must be rejected before the body is read into memory")
	}
	if err := ValidateBatchSize(1<<40, 0); err != nil {
		t.Error("a zero limit means unbounded")
	}
}

// TestTruncateRecordReportsTruncation: silent truncation would let a rule
// evaluation run against a partial body and report a confident wrong answer.
func TestTruncateRecordReportsTruncation(t *testing.T) {
	small := []byte("short record")
	out, truncated := TruncateRecord(small)
	if truncated || len(out) != len(small) {
		t.Error("a small record must pass through untouched")
	}

	big := []byte(strings.Repeat("x", MaxRecordBytes+100))
	out, truncated = TruncateRecord(big)
	if !truncated {
		t.Fatal("truncation must be reported, never silent")
	}
	if len(out) != MaxRecordBytes {
		t.Errorf("truncated to %d, want %d", len(out), MaxRecordBytes)
	}
}

func TestMemoryDeduperCollapsesRedelivery(t *testing.T) {
	d := NewMemoryDeduper()
	ctx := context.Background()

	isNew, err := d.Seen(ctx, "cf:ray-1")
	if err != nil || !isNew {
		t.Fatalf("first sighting should be new: %v %v", isNew, err)
	}
	isNew, err = d.Seen(ctx, "cf:ray-1")
	if err != nil || isNew {
		t.Fatal("redelivery must not be treated as new; at-least-once delivery is routine")
	}
	if isNew, _ := d.Seen(ctx, "cf:ray-2"); !isNew {
		t.Error("a different record must still be new")
	}
}

func TestMemoryBufferCounts(t *testing.T) {
	b := &MemoryBuffer{}
	ctx := context.Background()
	if err := b.Append(ctx, RawBatch{Records: [][]byte{[]byte("a"), []byte("b")}}); err != nil {
		t.Fatal(err)
	}
	if err := b.Append(ctx, RawBatch{Records: [][]byte{[]byte("c")}}); err != nil {
		t.Fatal(err)
	}
	if b.RecordCount() != 3 {
		t.Errorf("expected 3 records across 2 batches, got %d", b.RecordCount())
	}
}

func TestMemoryDeadLetterRetainsOriginalBytes(t *testing.T) {
	dl := &MemoryDeadLetter{}
	original := []byte(`{"partial":`)
	if err := dl.Put(context.Background(), DeadLetterRecord{
		Payload: original, FailureReason: "malformed JSON", ReprocessState: ReprocessPending,
	}); err != nil {
		t.Fatal(err)
	}
	if len(dl.Records) != 1 {
		t.Fatalf("expected one dead-letter record, got %d", len(dl.Records))
	}
	if string(dl.Records[0].Payload) != string(original) {
		t.Error("the ORIGINAL bytes must survive; a parser fix weeks later depends on them")
	}
}
