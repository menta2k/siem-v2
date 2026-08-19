package jetstream

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/menta2k/siem-v2/backend/internal/ingest"
)

// TestSplitBatchKeepsEveryChunkUnderTheLimit is the bug the burst test found:
// a 6,000-record Logpush delivery marshals past NATS's 1 MiB max_payload, and
// publishing it whole fails at the server — every large batch came back 503.
func TestSplitBatchKeepsEveryChunkUnderTheLimit(t *testing.T) {
	batch := ingest.RawBatch{BatchID: "big", Provider: "cloudflare", Tenant: "acme"}
	record := bytes.Repeat([]byte("x"), 230)
	for i := 0; i < 6000; i++ {
		batch.Records = append(batch.Records, record)
	}

	chunks := splitBatch(batch, maxMessageBytes)
	if len(chunks) < 2 {
		t.Fatalf("1.4MB of records must split, got %d chunk(s)", len(chunks))
	}

	total := 0
	for i, c := range chunks {
		payload, err := json.Marshal(c)
		if err != nil {
			t.Fatalf("chunk %d: %v", i, err)
		}
		if len(payload) > maxMessageBytes {
			t.Errorf("chunk %d marshals to %d bytes, over the %d limit", i, len(payload), maxMessageBytes)
		}
		if c.Tenant != "acme" || c.Provider != "cloudflare" {
			t.Errorf("chunk %d lost its envelope: %+v", i, c)
		}
		total += len(c.Records)
	}
	if total != 6000 {
		t.Fatalf("chunking must lose nothing: %d of 6000 records survived", total)
	}
}

func TestSmallBatchStaysWhole(t *testing.T) {
	batch := ingest.RawBatch{BatchID: "small", Records: [][]byte{[]byte("one"), []byte("two")}}
	chunks := splitBatch(batch, maxMessageBytes)
	if len(chunks) != 1 || len(chunks[0].Records) != 2 {
		t.Fatalf("a small batch must not be split, got %d chunks", len(chunks))
	}
}

func TestEmptyBatchSurvives(t *testing.T) {
	if got := splitBatch(ingest.RawBatch{BatchID: "empty"}, maxMessageBytes); len(got) != 1 {
		t.Fatalf("an empty batch is one (empty) chunk, got %d", len(got))
	}
}

// TestChunkOrderIsRecordOrder: replay depends on records staying in delivery
// order across the chunk boundary.
func TestChunkOrderIsRecordOrder(t *testing.T) {
	batch := ingest.RawBatch{BatchID: "ordered"}
	for i := 0; i < 5000; i++ {
		batch.Records = append(batch.Records, []byte{byte(i % 256), byte(i / 256)})
	}
	var rebuilt [][]byte
	for _, c := range splitBatch(batch, 4096) {
		rebuilt = append(rebuilt, c.Records...)
	}
	if len(rebuilt) != 5000 {
		t.Fatalf("lost records: %d", len(rebuilt))
	}
	for i, rec := range rebuilt {
		if rec[0] != byte(i%256) || rec[1] != byte(i/256) {
			t.Fatalf("record %d out of order", i)
		}
	}
}
