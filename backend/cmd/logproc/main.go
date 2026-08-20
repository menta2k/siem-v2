// Command logproc is the collection tier: it receives provider deliveries,
// buffers them durably, parses, correlates and stores flows.
//
// It is a separate binary from apiserver because FR-065 and SC-022 require
// collection to continue while the analysis tier is down. Sharing a process
// would make that impossible to honour.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/menta2k/siem-v2/backend/internal/biz/flow"
	"github.com/menta2k/siem-v2/backend/internal/conf"
	"github.com/menta2k/siem-v2/backend/internal/correlate/window"
	"github.com/menta2k/siem-v2/backend/internal/data/jetstream"
	"github.com/menta2k/siem-v2/backend/internal/data/postgres"
	datavalkey "github.com/menta2k/siem-v2/backend/internal/data/valkey"
	"github.com/menta2k/siem-v2/backend/internal/data/victorialogs"
	"github.com/menta2k/siem-v2/backend/internal/ingest"
	"github.com/menta2k/siem-v2/backend/internal/ingest/feedauth"
	"github.com/menta2k/siem-v2/backend/internal/ingest/filter"
	"github.com/menta2k/siem-v2/backend/internal/ingest/logpush"
	"github.com/menta2k/siem-v2/backend/internal/ingest/vectorhttp"
	"github.com/menta2k/siem-v2/backend/internal/normalize"
	"github.com/menta2k/siem-v2/backend/internal/normalize/cloudflare"
	"github.com/menta2k/siem-v2/backend/internal/normalize/datadome"
	"github.com/menta2k/siem-v2/backend/internal/normalize/f5asm"
	"github.com/menta2k/siem-v2/backend/internal/normalize/nginx"
	"github.com/menta2k/siem-v2/backend/internal/normalize/schema"
	"github.com/menta2k/siem-v2/backend/internal/observability"
	"github.com/menta2k/siem-v2/backend/internal/version"
	valkeygo "github.com/valkey-io/valkey-go"
)

func main() {
	confPath := flag.String("conf", "configs/logproc.yaml", "path to the configuration file")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	logger.Info("starting", "version", version.String())
	if err := run(*confPath, logger); err != nil {
		logger.Error("logproc exited", "error", err)
		os.Exit(1)
	}
}

func run(confPath string, logger *slog.Logger) error {
	cfg, err := conf.Load(confPath)
	if err != nil {
		return err
	}

	buffer, err := jetstream.Connect(jetstream.Config{
		URL:        cfg.Storage.JetStream.URL,
		StreamName: cfg.Storage.JetStream.StreamName,
		Subject:    "siem.raw",
		MaxAge:     time.Duration(cfg.Storage.JetStream.MaxAgeDays) * 24 * time.Hour,
	})
	if err != nil {
		return fmt.Errorf("ingest buffer: %w", err)
	}
	defer buffer.Close()
	logger.Info("connected to ingest buffer", "url", cfg.Storage.JetStream.URL)

	vl := victorialogs.New(cfg.Storage.VictoriaLogs.Hot, nil)
	tenant := victorialogs.Tenant{
		AccountID: cfg.Storage.VictoriaLogs.AccountID,
		ProjectID: cfg.Storage.VictoriaLogs.ProjectID,
	}
	if err := vl.Ping(context.Background()); err != nil {
		return fmt.Errorf("victorialogs unreachable: %w", err)
	}
	logger.Info("connected to victorialogs", "url", cfg.Storage.VictoriaLogs.Hot)

	health := observability.NewRegistry()
	pipeline := buildPipeline(vl, tenant, cfg, health, logger)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Correlation state survives restart (FR-023): a deploy must resume the
	// in-flight window, not discard every flow whose window was still open.
	// Best-effort — a Valkey outage degrades to the pre-existing behaviour
	// (lose the in-flight window on restart) rather than blocking startup.
	corrState := buildCorrelationState(cfg, logger)
	if corrState != nil {
		if states, err := corrState.Load(ctx); err != nil {
			logger.Warn("could not load correlation window; starting empty", "error", err)
		} else if len(states) > 0 {
			pipeline.Restore(states)
			_ = corrState.Clear(ctx) // consumed; a later crash must not replay it
			logger.Info("restored in-flight correlation window", "states", len(states))
		}
	}

	// Per-feed ingest credentials live in Postgres, served here from a
	// refreshed in-memory snapshot. Postgres being down keeps ingest running
	// on the last snapshot; only a store that has NEVER loaded answers 503.
	feedStore, sourceRepo, filterRepo := buildFeedStore(ctx, cfg, health, logger)

	// Tenant ingest filters, refreshed like the feed credentials. Every
	// failure keeps the previous snapshot or yields "no filters" — dropping
	// is irreversible, so this path fails OPEN by design.
	filterCache := newFilterCache(filterRepo, logger)
	go filterCache.run(ctx)
	pipeline.Filters = filterCache.setFor
	var filteredLogMu sync.Mutex
	lastFilteredLog := map[string]time.Time{}
	pipeline.OnFiltered = func(tenant string, provider schema.Provider, count int) {
		filteredLogMu.Lock()
		defer filteredLogMu.Unlock()
		k := tenant + "/" + string(provider)
		if time.Since(lastFilteredLog[k]) >= time.Minute {
			lastFilteredLog[k] = time.Now()
			logger.Info("records dropped by ingest filter (rate-limited: one line per tenant+provider per minute)",
				"tenant", tenant, "provider", provider, "count", count)
		}
	}

	srv := ingestServer(cfg, buffer, health, feedStore, logger)
	go func() {
		logger.Info("ingest listening", "addr", cfg.Server.HTTPAddr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("ingest server failed", "error", err)
			stop()
		}
	}()

	go consume(ctx, buffer, pipeline, health, logger)
	go flushLoop(ctx, pipeline, logger)
	go silenceLoop(ctx, health, sourceRepo, logger)

	<-ctx.Done()
	logger.Info("shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	// Draining in-flight flows on shutdown means a restart resumes from a clean
	// point rather than replaying the tail unnecessarily.
	if n, err := pipeline.Flush(shutdownCtx); err == nil && n > 0 {
		logger.Info("flushed flows during shutdown", "count", n)
	}
	// Persist whatever remains open so the next boot resumes it (FR-023).
	if corrState != nil {
		states := pipeline.Snapshot()
		if err := corrState.Save(shutdownCtx, states); err != nil {
			logger.Warn("could not persist correlation window", "error", err)
		} else {
			logger.Info("persisted in-flight correlation window", "states", len(states))
		}
	}
	return srv.Shutdown(shutdownCtx)
}

func buildPipeline(vl *victorialogs.Client, tenant victorialogs.Tenant,
	cfg *conf.Config, health *observability.Registry, logger *slog.Logger) *flow.Pipeline {

	repo := victorialogs.NewFlowRepo(vl, tenant)
	w := window.New(window.Options{
		LateArrival:    cfg.Correlate.LateArrivalWindow,
		ExpectedLayers: 4,
	})

	p := flow.NewPipeline(repo, &ingest.MemoryDeadLetter{}, w)
	// The same repo serves as loader, enabling merge-on-close for stragglers
	// that arrive after their flow closed (batch-delivered providers).
	p.Loader = repo
	// The token key turns a sensitive value into a stable pseudonym, so an
	// analyst can still see that the same value recurred without ever seeing it.
	// Absent a key, sensitive values are plainly masked rather than left readable.
	p.Masker = normalize.NewMasker([]byte(os.Getenv("SIEM_TOKEN_KEY")))
	p.Register(cloudflare.New())
	p.Register(datadome.New())
	p.Register(f5asm.New())
	p.Register(nginx.New())

	// Rate-limited to one line per provider per minute: 274,000 records once
	// failed to parse without a single log line, because the failure path only
	// bumped a rate nothing rendered. The ERROR carries the parser's own
	// reason, which names the missing field or bad layout directly.
	var parseLogMu sync.Mutex
	lastParseLog := map[schema.Provider]time.Time{}
	p.OnParseFailure = func(provider schema.Provider, err error) {
		health.RecordParseFailureRate(string(provider), 1)
		parseLogMu.Lock()
		now := time.Now()
		if now.Sub(lastParseLog[provider]) >= time.Minute {
			lastParseLog[provider] = now
			parseLogMu.Unlock()
			logger.Error("records failing to parse (rate-limited: one line per provider per minute)",
				"provider", provider, "reason", err.Error())
			return
		}
		parseLogMu.Unlock()
	}
	return p
}

// feedLister adapts the postgres feed repository to the feedauth cache.
type feedLister struct{ repo *postgres.FeedRepo }

func (l feedLister) ListEnabled(ctx context.Context) ([]feedauth.Feed, error) {
	if l.repo == nil {
		return nil, fmt.Errorf("feed store has no database")
	}
	rows, err := l.repo.ListEnabled(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]feedauth.Feed, 0, len(rows))
	for _, f := range rows {
		out = append(out, feedauth.Feed{
			ID: f.ID, TenantID: f.TenantID, Provider: f.Provider,
			Name: f.Name, TokenHash: f.TokenHash,
		})
	}
	return out, nil
}

// buildFeedStore connects to Postgres and starts the refresh loop. A missing
// DSN or unreachable database does not stop ingest — the legacy shared-secret
// routes keep working and the feed routes answer 503 until the first load.
func buildFeedStore(ctx context.Context, cfg *conf.Config,
	health *observability.Registry, logger *slog.Logger) (*feedauth.Store, *postgres.SourceRepo, *postgres.FilterRepo) {

	dsn := os.Getenv("SIEM_PG_DSN")
	if dsn == "" {
		logger.Warn("SIEM_PG_DSN unset; per-feed ingest routes will answer 503")
		return feedauth.NewStore(feedLister{}, 30*time.Second, logger), nil, nil
	}
	pool, err := postgres.Connect(ctx, dsn, int32(cfg.Storage.Postgres.MaxConns), cfg.Storage.Postgres.MinConns)
	if err != nil {
		// Ingest must outlive a database outage at startup: the legacy routes
		// keep working and the feed routes answer 503 (senders retry).
		logger.Warn("postgres unreachable; per-feed ingest routes will answer 503", "error", err)
		return feedauth.NewStore(feedLister{}, 30*time.Second, logger), nil, nil
	}
	store := feedauth.NewStore(feedLister{repo: postgres.NewFeedRepo(pool)}, 30*time.Second, logger)
	go store.Run(ctx)
	return store, postgres.NewSourceRepo(pool), postgres.NewFilterRepo(pool)
}

func ingestServer(cfg *conf.Config, buffer *jetstream.Buffer,
	health *observability.Registry, feedStore *feedauth.Store, logger *slog.Logger) *http.Server {

	secret := os.Getenv("SIEM_INGEST_SECRET")
	mux := http.NewServeMux()

	cfReceiver := &logpush.Receiver{
		Buffer: buffer, Secret: secret, Tenant: "acme",
		SourceID: "cf-1", MaxBodyBytes: cfg.Ingest.MaxBodyBytes,
		OnValidation: func() { logger.Info("cloudflare destination validation accepted") },
	}
	// Method-specific so these literal routes coexist with the per-feed
	// wildcard below (a method-less pattern conflicts with a method-ful one).
	mux.Handle("POST /ingest/v1/cloudflare/logpush", cfReceiver)
	mux.Handle("PUT /ingest/v1/cloudflare/logpush", cfReceiver)

	for _, s := range []struct {
		path     string
		sourceID string
		provider schema.Provider
	}{
		{"/ingest/v1/vector/nginx", "ngx-1", schema.ProviderNginx},
		{"/ingest/v1/vector/f5asm", "f5-1", schema.ProviderF5ASM},
		{"/ingest/v1/vector/datadome", "dd-1", schema.ProviderDataDome},
	} {
		mux.Handle("POST "+s.path, &vectorhttp.Receiver{
			Buffer: buffer, Secret: secret, Tenant: "acme",
			SourceID: s.sourceID, Provider: s.provider,
			MaxBodyBytes: cfg.Ingest.MaxBodyBytes,
		})
		health.RegisterSource(s.sourceID, string(s.provider), 15*time.Minute)
	}
	health.RegisterSource("cf-1", string(schema.ProviderCloudflare), 15*time.Minute)

	// Per-feed routes, alongside the legacy shared-secret ones. The URL shape
	// (/ingest/v1/{provider}/{feed_id}) is v1's, so its vendor-configuration
	// documentation transfers unchanged.
	feedHandler := &feedauth.Handler{
		Store: feedStore, Buffer: buffer, MaxBodyBytes: cfg.Ingest.MaxBodyBytes,
		Logger: logger,
		OnAccepted: func(f feedauth.Feed) {
			health.RegisterSource(f.ID, f.Provider, 15*time.Minute)
			// Silence means "nothing is ARRIVING", judged at accept time.
			// Feeding the clock from the consumer (which stamps batches with
			// their original receive time) made a lagging consumer look like
			// hours of silent sources during a backlog drain.
			health.RecordDelivery(f.ID, 1, time.Now())
		},
	}
	feedHandler.Mount(mux)

	// Health asserts meaningful output, not merely that the process is alive
	// (Constitution IV).
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		state := health.Overall()
		if state != observability.StateHealthy {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		fmt.Fprintf(w, `{"status":%q}`, state)
	})

	return &http.Server{
		Addr:         cfg.Server.HTTPAddr,
		Handler:      mux,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}
}

// consume drains the durable buffer into the pipeline.
//
// Acknowledgement is handled by the buffer only after ProcessBatch returns nil,
// so a processing failure redelivers rather than silently dropping the batch.
func consume(ctx context.Context, buffer *jetstream.Buffer,
	pipeline *flow.Pipeline, health *observability.Registry, logger *slog.Logger) {

	err := buffer.Consume(ctx, "logproc", func(ctx context.Context, batch ingest.RawBatch) error {
		if err := pipeline.ProcessBatch(ctx, batch); err != nil {
			logger.Error("process batch failed",
				"provider", batch.Provider, "batch_id", batch.BatchID, "error", err)
			return err
		}
		health.RecordDelivery(batch.SourceID, len(batch.Records), batch.ReceivedAt)
		logger.Info("batch processed",
			"provider", batch.Provider, "records", len(batch.Records))
		return nil
	})
	if err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("buffer consumer stopped", "error", err)
	}
}

func flushLoop(ctx context.Context, pipeline *flow.Pipeline, logger *slog.Logger) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pipeline.Correlate()
			n, err := pipeline.Flush(ctx)
			if err != nil {
				logger.Error("flush failed", "error", err)
				continue
			}
			if n > 0 {
				logger.Info("flows stored", "count", n, "in_flight", pipeline.InFlight())
			}
		}
	}
}

// silenceLoop is what turns a quiet vendor into a visible condition. The
// registry's EvaluateSilence marks sources whose cadence has lapsed — but
// marking only happens when someone asks, and until this loop existed nobody
// did in production: /health reported "healthy" through hours of silence
// because the evaluation only ever ran inside a test.
func silenceLoop(ctx context.Context, health *observability.Registry,
	sources *postgres.SourceRepo, logger *slog.Logger) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	wasSilent := map[string]bool{}
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			silent := map[string]bool{}
			for _, s := range health.EvaluateSilence(now) {
				silent[s.SourceID] = true
				if !wasSilent[s.SourceID] {
					logger.Warn("source went silent",
						"source", s.SourceID, "provider", s.Provider,
						"last_record_at", s.LastRecordAt,
						"expected_cadence", s.ExpectedCadence.String())
				}
			}
			for id := range wasSilent {
				if !silent[id] {
					logger.Info("source recovered from silence", "source", id)
				}
			}
			wasSilent = silent

			// The Sources page reads Postgres, and logproc is the only
			// component that actually sees deliveries — sync the observed
			// state so the page stops saying "awaiting" forever.
			if sources != nil {
				for _, src := range health.Sources() {
					var last *time.Time
					if !src.LastRecordAt.IsZero() {
						at := src.LastRecordAt
						last = &at
					}
					if err := sources.UpdateHealth(ctx, src.SourceID, string(src.State), last); err != nil {
						logger.Warn("source health sync failed", "source", src.SourceID, "error", err)
					}
				}
			}
		}
	}
}

// filterCache serves compiled per-tenant filter sets from a 30s-refresh
// snapshot, failing open at every step.
type filterCache struct {
	repo   *postgres.FilterRepo
	logger *slog.Logger
	mu     sync.RWMutex
	sets   map[string]*filter.Set
}

func newFilterCache(repo *postgres.FilterRepo, logger *slog.Logger) *filterCache {
	return &filterCache{repo: repo, logger: logger, sets: map[string]*filter.Set{}}
}

func (c *filterCache) run(ctx context.Context) {
	if c.repo == nil {
		return
	}
	c.refresh(ctx)
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.refresh(ctx)
		}
	}
}

func (c *filterCache) refresh(ctx context.Context) {
	all, err := c.repo.All(ctx)
	if err != nil {
		c.logger.Warn("ingest filter refresh failed; previous rules keep applying", "error", err)
		return
	}
	next := make(map[string]*filter.Set, len(all))
	for tenant, rules := range all {
		set, err := filter.Compile(rules)
		if err != nil {
			// A rule set the API validated should never fail here, but if it
			// does the tenant ingests everything rather than losing data.
			c.logger.Warn("stored ingest filters do not compile; ignoring them", "tenant", tenant, "error", err)
			continue
		}
		next[tenant] = set
	}
	c.mu.Lock()
	c.sets = next
	c.mu.Unlock()
}

func (c *filterCache) setFor(tenant string) *filter.Set {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.sets[tenant] // nil = keep everything
}

// buildCorrelationState connects the Valkey-backed window persistence, or
// returns nil (restart still works, just without resuming the in-flight
// window) when Valkey is unconfigured or unreachable.
func buildCorrelationState(cfg *conf.Config, logger *slog.Logger) *datavalkey.CorrelationState {
	if len(cfg.Storage.Valkey.Addrs) == 0 {
		return nil
	}
	client, err := valkeygo.NewClient(valkeygo.ClientOption{InitAddress: cfg.Storage.Valkey.Addrs})
	if err != nil {
		logger.Warn("valkey unavailable; the in-flight window will not survive restart", "error", err)
		return nil
	}
	return datavalkey.NewCorrelationState(client)
}
