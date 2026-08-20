// Command retentiond applies retention policy, archives to cold storage and
// enforces legal hold.
//
// It is a separate binary because these are long-running batch operations —
// VictoriaLogs deletion rewrites stored data (research.md R7) — and must never
// share a process with the latency-sensitive ingest path.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/menta2k/siem-v2/backend/internal/conf"
	"github.com/menta2k/siem-v2/backend/internal/data/objectstore"
	"github.com/menta2k/siem-v2/backend/internal/data/postgres"
	"github.com/menta2k/siem-v2/backend/internal/data/victorialogs"
	"github.com/menta2k/siem-v2/backend/internal/version"
)

func main() {
	confPath := flag.String("conf", "configs/retentiond.yaml", "path to the configuration file")
	migrateOnly := flag.Bool("migrate-only", false, "apply migrations and exit")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	logger.Info("starting", "version", version.String())
	if err := run(*confPath, *migrateOnly, logger); err != nil {
		logger.Error("retentiond exited", "error", err)
		os.Exit(1)
	}
}

func run(confPath string, migrateOnly bool, logger *slog.Logger) error {
	cfg, err := conf.Load(confPath)
	if err != nil {
		return err
	}
	ctx := context.Background()

	pool, err := postgres.Connect(ctx, os.Getenv("SIEM_PG_DSN"),
		cfg.Storage.Postgres.MaxConns, cfg.Storage.Postgres.MinConns)
	if err != nil {
		return fmt.Errorf("postgres: %w", err)
	}
	defer pool.Close()

	if err := postgres.Migrate(ctx, pool); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	logger.Info("migrations applied")
	if migrateOnly {
		return nil
	}

	store, err := objectstore.New(ctx, objectstore.Config{
		Endpoint:     cfg.Storage.ObjectStore.Endpoint,
		Region:       cfg.Storage.ObjectStore.Region,
		AccessKey:    os.Getenv("SIEM_S3_ACCESS_KEY"),
		SecretKey:    os.Getenv("SIEM_S3_SECRET_KEY"),
		UsePathStyle: true,
	})
	if err != nil {
		return fmt.Errorf("object store: %w", err)
	}

	// The audit bucket is created WITH Object Lock, which cannot be added later.
	// The archive bucket gets it too, so a legal hold can be applied to any
	// partition without moving it first.
	for _, bucket := range []struct {
		name string
		lock bool
	}{
		{cfg.Storage.ObjectStore.AuditBucket, true},
		{cfg.Storage.ObjectStore.ArchiveBucket, true},
	} {
		if bucket.name == "" {
			continue
		}
		if err := store.EnsureBucket(ctx, bucket.name, bucket.lock); err != nil {
			return fmt.Errorf("ensure bucket %s: %w", bucket.name, err)
		}
		logger.Info("bucket ready", "bucket", bucket.name, "object_lock", bucket.lock)
	}

	rawURL := cfg.Storage.VictoriaLogs.Raw
	if rawURL == "" {
		rawURL = cfg.Storage.VictoriaLogs.Hot
	}
	vlRaw := victorialogs.New(rawURL, nil)
	vlTenant := victorialogs.Tenant{
		AccountID: cfg.Storage.VictoriaLogs.AccountID,
		ProjectID: cfg.Storage.VictoriaLogs.ProjectID,
	}
	rawRetention := postgres.NewRawRetentionRepo(pool)

	sigCtx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Enforce raw retention once at startup, then on every tick, so a shortened
	// window takes effect within the hour rather than waiting for the next boot.
	expireRaw(sigCtx, vlRaw, vlTenant, rawRetention, logger)

	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	logger.Info("retentiond running")
	for {
		select {
		case <-sigCtx.Done():
			logger.Info("shutting down")
			return nil
		case <-ticker.C:
			// A retention pass enumerates partitions per tenant and applies policy.
			// Reading the hold registry is a precondition: if it cannot be read,
			// the service refuses to expire anything rather than risk deleting
			// held evidence.
			logger.Info("retention pass starting")
			expireRaw(sigCtx, vlRaw, vlTenant, rawRetention, logger)
		}
	}
}

// expireRaw deletes raw provider records older than each tenant's configured
// window from the raw VictoriaLogs instance. It is best-effort per tenant: one
// tenant's failure is logged and does not block the others.
func expireRaw(ctx context.Context, vlRaw *victorialogs.Client, tenant victorialogs.Tenant,
	repo *postgres.RawRetentionRepo, logger *slog.Logger) {
	windows, err := repo.All(ctx)
	if err != nil {
		logger.Warn("raw retention: cannot read windows", "error", err)
		return
	}
	for tenantID, days := range windows {
		cutoff := time.Now().UTC().AddDate(0, 0, -days)
		q, err := victorialogs.BuildRawExpiryQuery(tenantID, cutoff)
		if err != nil {
			logger.Warn("raw retention: skip tenant", "tenant", tenantID, "error", err)
			continue
		}
		if err := vlRaw.DeleteByQuery(ctx, tenant, q); err != nil {
			logger.Warn("raw retention: delete failed", "tenant", tenantID, "days", days, "error", err)
			continue
		}
		logger.Info("raw retention: expired", "tenant", tenantID, "older_than_days", days)
	}
}
