//go:build integration

// Package integration holds tests that run against real dependencies.
package integration

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awscfg "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// TestObjectLockConformance resolves verification item V9.
//
// The design of this test is the point of it. Object Lock is what makes two spec
// requirements TRUE rather than merely claimed:
//
//   - FR-040, legal hold: held data survives its retention expiry.
//   - FR-055, an audit trail operators cannot alter.
//
// A store can accept every Object Lock API call and still permit the delete. That
// failure mode is invisible from the API surface and would leave the system
// looking compliant while the guarantee silently did not exist. So the pass
// condition here is NOT "the calls succeeded" — it is "the delete was REFUSED".
//
// This matters more than a routine dependency check because RustFS has not
// reached a stable 1.0, its maintainers advise against production use until it
// does, and its Object Lock support is claimed in documentation that 404s and is
// absent from the README (research.md R13).
func TestObjectLockConformance(t *testing.T) {
	endpoint := envOr("SIEM_TEST_S3_ENDPOINT", "http://localhost:9000")
	client := s3Client(t, endpoint)
	ctx := context.Background()

	bucket := fmt.Sprintf("siem-objectlock-%d", time.Now().UnixNano())

	// STEP 1 — Object Lock can only be enabled AT BUCKET CREATION. It cannot be
	// retrofitted, which is why the quickstart calls this out as a config item
	// that must be right before any data is loaded.
	_, err := client.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket:                     aws.String(bucket),
		ObjectLockEnabledForBucket: aws.Bool(true),
	})
	if err != nil {
		t.Fatalf("STEP 1 FAILED — CreateBucket with ObjectLockEnabledForBucket: %v\n"+
			"V9 VERDICT: the store cannot create an Object Lock bucket at all. "+
			"FR-040 and FR-055 cannot be satisfied here; point the audit/hold bucket "+
			"at a mature store (see research.md R13 fallbacks).", err)
	}
	t.Cleanup(func() { cleanupBucket(context.Background(), t, client, bucket) })
	t.Log("STEP 1 OK — bucket created with Object Lock enabled")

	// STEP 2 — a default retention rule on the bucket.
	_, err = client.PutObjectLockConfiguration(ctx, &s3.PutObjectLockConfigurationInput{
		Bucket: aws.String(bucket),
		ObjectLockConfiguration: &types.ObjectLockConfiguration{
			ObjectLockEnabled: types.ObjectLockEnabledEnabled,
			Rule: &types.ObjectLockRule{
				DefaultRetention: &types.DefaultRetention{
					Mode: types.ObjectLockRetentionModeCompliance,
					Days: aws.Int32(1),
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("STEP 2 FAILED — PutObjectLockConfiguration: %v", err)
	}
	t.Log("STEP 2 OK — default COMPLIANCE retention configured")

	// STEP 3 — write an object standing in for an audit export.
	key := "audit/2026-08-19.jsonl"
	body := []byte(`{"actor":"analyst-1","action":"export","at":"2026-08-19T00:00:00Z"}`)
	put, err := client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader(body),
	})
	if err != nil {
		t.Fatalf("STEP 3 FAILED — PutObject: %v", err)
	}
	version := aws.ToString(put.VersionId)
	if version == "" {
		t.Error("STEP 3 WARNING — no VersionId returned. Object Lock requires versioning; " +
			"without per-version ids, retention cannot be pinned to a specific version.")
	}
	t.Logf("STEP 3 OK — object written, version=%q", version)

	// STEP 4 — pin COMPLIANCE retention to that version. COMPLIANCE, not
	// GOVERNANCE: governance mode is bypassable by a privileged caller, which is
	// precisely the operator we are protecting the audit trail against.
	retainUntil := time.Now().Add(24 * time.Hour)
	_, err = client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
		Bucket:    aws.String(bucket),
		Key:       aws.String(key),
		VersionId: aws.String(version),
		Retention: &types.ObjectLockRetention{
			Mode:            types.ObjectLockRetentionModeCompliance,
			RetainUntilDate: aws.Time(retainUntil),
		},
	})
	if err != nil {
		t.Fatalf("STEP 4 FAILED — PutObjectRetention: %v", err)
	}
	t.Log("STEP 4 OK — COMPLIANCE retention applied to the version")

	// STEP 5 — THE ACTUAL TEST. Everything above only proves the API accepts
	// calls. This proves the guarantee.
	_, err = client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket:    aws.String(bucket),
		Key:       aws.String(key),
		VersionId: aws.String(version),
	})
	if err == nil {
		t.Fatal("STEP 5 FAILED — THE RETAINED VERSION WAS DELETED.\n" +
			"V9 VERDICT: FAIL. The store accepts every Object Lock API call and then " +
			"permits the delete anyway. This is the silent-non-guarantee this test exists " +
			"to catch: the system would look compliant while FR-040 and FR-055 were false.\n" +
			"ACTION: point the audit/hold bucket at MinIO or cloud S3 (research.md R13).")
	}
	t.Logf("STEP 5 OK — delete of the retained version was REFUSED: %v", err)

	// STEP 6 — legal hold, the FR-040 mechanism, is independent of retention.
	_, err = client.PutObjectLegalHold(ctx, &s3.PutObjectLegalHoldInput{
		Bucket:    aws.String(bucket),
		Key:       aws.String(key),
		VersionId: aws.String(version),
		LegalHold: &types.ObjectLockLegalHold{Status: types.ObjectLockLegalHoldStatusOn},
	})
	if err != nil {
		t.Fatalf("STEP 6 FAILED — PutObjectLegalHold: %v\n"+
			"V9 VERDICT: PARTIAL. Retention is enforced but legal hold is unavailable, "+
			"so FR-040 cannot rely on the store.", err)
	}
	t.Log("STEP 6 OK — legal hold applied")

	got, err := client.GetObjectLegalHold(ctx, &s3.GetObjectLegalHoldInput{
		Bucket: aws.String(bucket), Key: aws.String(key), VersionId: aws.String(version),
	})
	if err != nil || got.LegalHold == nil || got.LegalHold.Status != types.ObjectLockLegalHoldStatusOn {
		t.Logf("STEP 6 NOTE — legal hold read-back: err=%v status=%+v", err, got)
	}

	// STEP 7 — an overwrite must not destroy the retained version. S3 semantics
	// allow a new version; what must survive is the old one.
	_, err = client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucket), Key: aws.String(key),
		Body: bytes.NewReader([]byte(`{"actor":"attacker","action":"tamper"}`)),
	})
	if err != nil {
		t.Logf("STEP 7 NOTE — overwrite rejected outright: %v", err)
	}
	orig, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket), Key: aws.String(key), VersionId: aws.String(version),
	})
	if err != nil {
		t.Fatalf("STEP 7 FAILED — the retained version is no longer readable after overwrite: %v\n"+
			"V9 VERDICT: FAIL. An overwrite destroyed protected data.", err)
	}
	defer orig.Body.Close()
	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(orig.Body); err != nil {
		t.Fatalf("read retained version: %v", err)
	}
	if !bytes.Equal(buf.Bytes(), body) {
		t.Fatalf("STEP 7 FAILED — retained version content changed.\nV9 VERDICT: FAIL, data is mutable.")
	}
	t.Log("STEP 7 OK — the retained version survived an overwrite intact")

	// STEP 8 — legal hold ISOLATED from retention. Steps 5–7 proved retention is
	// enforced, but FR-040 (legal hold preserving data past its normal expiry)
	// depends on legal hold ALONE holding the line. An object with no retention
	// and only a hold is the exact shape of that requirement, so test it directly
	// rather than inferring it from the retention result.
	holdKey := "audit/hold-only.jsonl"
	holdBody := []byte(`{"case":"legal-hold-only"}`)
	holdPut, err := client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(holdKey),
		Body:   bytes.NewReader(holdBody),
		// Explicitly no retention: the bucket default would otherwise apply and
		// we would be re-testing step 5.
		ObjectLockMode:            types.ObjectLockModeGovernance,
		ObjectLockRetainUntilDate: aws.Time(time.Now().Add(2 * time.Second)),
	})
	if err != nil {
		t.Fatalf("STEP 8 SETUP FAILED — PutObject for hold-only case: %v", err)
	}
	holdVersion := aws.ToString(holdPut.VersionId)

	if _, err := client.PutObjectLegalHold(ctx, &s3.PutObjectLegalHoldInput{
		Bucket: aws.String(bucket), Key: aws.String(holdKey), VersionId: aws.String(holdVersion),
		LegalHold: &types.ObjectLockLegalHold{Status: types.ObjectLockLegalHoldStatusOn},
	}); err != nil {
		t.Fatalf("STEP 8 SETUP FAILED — PutObjectLegalHold: %v", err)
	}

	// Let the short governance retention lapse so only the legal hold remains.
	time.Sleep(3 * time.Second)

	_, err = client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(bucket), Key: aws.String(holdKey), VersionId: aws.String(holdVersion),
		BypassGovernanceRetention: aws.Bool(true),
	})
	if err == nil {
		t.Fatal("STEP 8 FAILED — an object under LEGAL HOLD was deleted once its retention lapsed.\n" +
			"V9 VERDICT: PARTIAL. Retention is enforced but legal hold is not, so FR-040 " +
			"cannot rely on the object store. The hold registry in retentiond remains the " +
			"primary enforcement (by design), but the defence-in-depth layer is absent.")
	}
	t.Logf("STEP 8 OK — delete under legal hold alone was REFUSED: %v", err)

	t.Log("=== V9 VERDICT: PASS — retention AND legal hold are independently ENFORCED, not merely accepted ===")
}

func s3Client(t *testing.T, endpoint string) *s3.Client {
	t.Helper()
	cfg, err := awscfg.LoadDefaultConfig(context.Background(),
		awscfg.WithRegion(envOr("SIEM_TEST_S3_REGION", "us-east-1")),
		awscfg.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			envOr("SIEM_TEST_S3_ACCESS_KEY", "siem_dev"),
			envOr("SIEM_TEST_S3_SECRET_KEY", "siem_dev_only"), "")),
	)
	if err != nil {
		t.Fatalf("load aws config: %v", err)
	}
	// Path-style addressing: self-hosted stores rarely have wildcard DNS for
	// virtual-host-style bucket addressing.
	return s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(endpoint)
		o.UsePathStyle = true
	})
}

// cleanupBucket removes what it can. Objects under COMPLIANCE retention are, by
// design, undeletable until the retain-until date — so a leftover bucket after a
// PASSING run is expected and correct, not a bug in the cleanup.
func cleanupBucket(ctx context.Context, t *testing.T, c *s3.Client, bucket string) {
	versions, err := c.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{Bucket: aws.String(bucket)})
	if err != nil {
		return
	}
	for _, v := range versions.Versions {
		_, _ = c.PutObjectLegalHold(ctx, &s3.PutObjectLegalHoldInput{
			Bucket: aws.String(bucket), Key: v.Key, VersionId: v.VersionId,
			LegalHold: &types.ObjectLockLegalHold{Status: types.ObjectLockLegalHoldStatusOff},
		})
		_, _ = c.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: aws.String(bucket), Key: v.Key, VersionId: v.VersionId,
		})
	}
	for _, m := range versions.DeleteMarkers {
		_, _ = c.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: aws.String(bucket), Key: m.Key, VersionId: m.VersionId,
		})
	}
	if _, err := c.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: aws.String(bucket)}); err != nil {
		var apiErr interface{ ErrorCode() string }
		if errors.As(err, &apiErr) && strings.Contains(apiErr.ErrorCode(), "NotEmpty") {
			t.Logf("cleanup: bucket %s retained (objects still under COMPLIANCE lock — expected on a PASS)", bucket)
		}
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
