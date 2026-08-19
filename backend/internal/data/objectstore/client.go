// Package objectstore wraps S3-compatible storage.
//
// Everything here speaks the S3 API and nothing else. RustFS is the deployment
// target, but no RustFS-specific call appears anywhere, so swapping to MinIO,
// Ceph RGW or cloud S3 is a configuration change (research.md R13). That
// portability is the mitigation for RustFS being pre-1.0.
package objectstore

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awscfg "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// Config addresses the store.
type Config struct {
	Endpoint     string
	Region       string
	AccessKey    string
	SecretKey    string
	UsePathStyle bool
}

// Client is an S3-compatible object store client.
type Client struct{ s3 *s3.Client }

func New(ctx context.Context, cfg Config) (*Client, error) {
	region := cfg.Region
	if region == "" {
		region = "us-east-1"
	}
	awsConf, err := awscfg.LoadDefaultConfig(ctx,
		awscfg.WithRegion(region),
		awscfg.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(cfg.AccessKey, cfg.SecretKey, "")),
	)
	if err != nil {
		return nil, fmt.Errorf("aws config: %w", err)
	}
	client := s3.NewFromConfig(awsConf, func(o *s3.Options) {
		if cfg.Endpoint != "" {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
		}
		// Self-hosted stores rarely have wildcard DNS for virtual-host addressing.
		o.UsePathStyle = cfg.UsePathStyle || cfg.Endpoint != ""
	})
	return &Client{s3: client}, nil
}

// EnsureBucket creates a bucket, optionally with Object Lock.
//
// Object Lock can ONLY be enabled at bucket creation — it cannot be retrofitted.
// Getting this wrong means recreating the bucket and re-copying everything in
// it, so the flag is an explicit parameter rather than a default.
func (c *Client) EnsureBucket(ctx context.Context, bucket string, objectLock bool) error {
	_, err := c.s3.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String(bucket)})
	if err == nil {
		return nil
	}
	input := &s3.CreateBucketInput{Bucket: aws.String(bucket)}
	if objectLock {
		input.ObjectLockEnabledForBucket = aws.Bool(true)
	}
	if _, err := c.s3.CreateBucket(ctx, input); err != nil {
		return fmt.Errorf("create bucket %s: %w", bucket, err)
	}
	return nil
}

// Put writes an object and returns its version id.
func (c *Client) Put(ctx context.Context, bucket, key string, body []byte) (string, error) {
	out, err := c.s3.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucket), Key: aws.String(key),
		Body: bytes.NewReader(body),
	})
	if err != nil {
		return "", fmt.Errorf("put %s/%s: %w", bucket, key, err)
	}
	return aws.ToString(out.VersionId), nil
}

// Get reads an object.
func (c *Client) Get(ctx context.Context, bucket, key string) ([]byte, error) {
	out, err := c.s3.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket), Key: aws.String(key),
	})
	if err != nil {
		return nil, fmt.Errorf("get %s/%s: %w", bucket, key, err)
	}
	defer out.Body.Close()
	return io.ReadAll(out.Body)
}

// ApplyRetention pins COMPLIANCE-mode retention to a version.
//
// COMPLIANCE, not GOVERNANCE: governance mode is bypassable by a sufficiently
// privileged caller, which is precisely the operator the audit trail is being
// protected against (FR-055).
func (c *Client) ApplyRetention(ctx context.Context, bucket, key, version string, until time.Time) error {
	_, err := c.s3.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
		Bucket: aws.String(bucket), Key: aws.String(key), VersionId: aws.String(version),
		Retention: &types.ObjectLockRetention{
			Mode:            types.ObjectLockRetentionModeCompliance,
			RetainUntilDate: aws.Time(until),
		},
	})
	if err != nil {
		return fmt.Errorf("apply retention to %s/%s: %w", bucket, key, err)
	}
	return nil
}

// SetLegalHold turns a hold on or off for a version.
func (c *Client) SetLegalHold(ctx context.Context, bucket, key, version string, on bool) error {
	status := types.ObjectLockLegalHoldStatusOff
	if on {
		status = types.ObjectLockLegalHoldStatusOn
	}
	_, err := c.s3.PutObjectLegalHold(ctx, &s3.PutObjectLegalHoldInput{
		Bucket: aws.String(bucket), Key: aws.String(key), VersionId: aws.String(version),
		LegalHold: &types.ObjectLockLegalHold{Status: status},
	})
	if err != nil {
		return fmt.Errorf("set legal hold on %s/%s: %w", bucket, key, err)
	}
	return nil
}

// Delete removes a version. It is expected to FAIL for anything under retention
// or legal hold; that failure is the guarantee working, not an error to retry.
func (c *Client) Delete(ctx context.Context, bucket, key, version string) error {
	in := &s3.DeleteObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)}
	if version != "" {
		in.VersionId = aws.String(version)
	}
	_, err := c.s3.DeleteObject(ctx, in)
	return err
}

// List returns keys under a prefix.
func (c *Client) List(ctx context.Context, bucket, prefix string) ([]string, error) {
	out, err := c.s3.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket: aws.String(bucket), Prefix: aws.String(prefix),
	})
	if err != nil {
		return nil, fmt.Errorf("list %s/%s: %w", bucket, prefix, err)
	}
	keys := make([]string, 0, len(out.Contents))
	for _, o := range out.Contents {
		keys = append(keys, aws.ToString(o.Key))
	}
	return keys, nil
}
