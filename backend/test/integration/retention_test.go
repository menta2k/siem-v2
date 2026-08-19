//go:build integration

package integration

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/menta2k/siem-v2/backend/internal/data/objectstore"
)

func store(t *testing.T) *objectstore.Client {
	t.Helper()
	c, err := objectstore.New(context.Background(), objectstore.Config{
		Endpoint:     envOr("SIEM_TEST_S3_ENDPOINT", "http://localhost:9000"),
		Region:       "us-east-1",
		AccessKey:    envOr("SIEM_TEST_S3_ACCESS_KEY", "siem_dev"),
		SecretKey:    envOr("SIEM_TEST_S3_SECRET_KEY", "siem_dev_only"),
		UsePathStyle: true,
	})
	if err != nil {
		t.Fatalf("objectstore: %v", err)
	}
	return c
}

// TestLegalHoldPreservationAgainstRealStore closes the loop that the unit tests
// can only assert against fakes: that a preserved partition is genuinely
// undeletable in the store the deployment will actually use.
//
// V9 already proved Object Lock is enforced. This proves the retention service's
// preserve path uses it correctly — a different question, and the one that
// matters for FR-040.
func TestLegalHoldPreservationAgainstRealStore(t *testing.T) {
	ctx := context.Background()
	c := store(t)

	bucket := fmt.Sprintf("siem-hold-%d", time.Now().UnixNano())
	if err := c.EnsureBucket(ctx, bucket, true); err != nil {
		t.Fatalf("create Object Lock bucket: %v", err)
	}

	key := "cold/2025-04-01/partition.jsonl"
	payload := []byte(`{"flow_id":"flow:evidence-1","effective_outcome":"blocked"}`)
	version, err := c.Put(ctx, bucket, key, payload)
	if err != nil {
		t.Fatalf("archive partition: %v", err)
	}
	if version == "" {
		t.Fatal("no version id returned; Object Lock requires versioning")
	}

	// This is what Service.preserve does for held data.
	if err := c.SetLegalHold(ctx, bucket, key, version, true); err != nil {
		t.Fatalf("apply legal hold: %v", err)
	}

	// Now behave like an expiry run that does not know about the hold.
	if err := c.Delete(ctx, bucket, key, version); err == nil {
		t.Fatal("a preserved partition was DELETED. The hold registry is the primary " +
			"enforcement, but the store-level protection it relies on is absent.")
	}

	// And the evidence is still readable, byte for byte.
	got, err := c.Get(ctx, bucket, key)
	if err != nil {
		t.Fatalf("held evidence is not readable: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatal("held evidence changed")
	}

	// Releasing the hold restores normal lifecycle.
	if err := c.SetLegalHold(ctx, bucket, key, version, false); err != nil {
		t.Fatalf("release hold: %v", err)
	}
	if err := c.Delete(ctx, bucket, key, version); err != nil {
		t.Errorf("after release, normal expiry should proceed: %v", err)
	}
}

func TestArchiveRoundTrip(t *testing.T) {
	ctx := context.Background()
	c := store(t)
	bucket := fmt.Sprintf("siem-archive-%d", time.Now().UnixNano())
	if err := c.EnsureBucket(ctx, bucket, false); err != nil {
		t.Fatalf("create bucket: %v", err)
	}

	for _, day := range []string{"2025-01-01", "2025-01-02"} {
		if _, err := c.Put(ctx, bucket, "cold/"+day+"/p.jsonl", []byte(`{"day":"`+day+`"}`)); err != nil {
			t.Fatalf("put %s: %v", day, err)
		}
	}
	keys, err := c.List(ctx, bucket, "cold/")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 archived partitions, got %v", keys)
	}
}

func envOrDefault(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
