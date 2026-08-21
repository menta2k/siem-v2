// Command profilerd is the traffic profiler: it consumes completed flows from
// the SIEM_FLOWS conveyor and learns per-endpoint behavioural baselines —
// which parameters each URL accepts, their types, and the structural ceilings
// of the requests that reach it.
//
// It is a separate binary for the same reason retentiond is: an unbounded-cost
// aggregation must never share a process with the latency-sensitive collection
// path. A profiler backlog degrades profile freshness, never ingest
// (Constitution I). Stopping profilerd stops profiling and nothing else.
package main

import (
	"context"
	"encoding/json"
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

	"github.com/nats-io/nats.go"

	"github.com/menta2k/siem-v2/backend/internal/conf"
	"github.com/menta2k/siem-v2/backend/internal/data/jetstream"
	"github.com/menta2k/siem-v2/backend/internal/data/postgres"
	"github.com/menta2k/siem-v2/backend/internal/profile"
	"github.com/menta2k/siem-v2/backend/internal/version"
)

func main() {
	confPath := flag.String("conf", "configs/profilerd.yaml", "path to the configuration file")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	logger.Info("starting", "version", version.String())
	if err := run(*confPath, logger); err != nil {
		logger.Error("profilerd exited", "error", err)
		os.Exit(1)
	}
}

func run(confPath string, logger *slog.Logger) error {
	cfg, err := conf.Load(confPath)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool, err := postgres.Connect(ctx, os.Getenv("SIEM_PG_DSN"),
		cfg.Storage.Postgres.MaxConns, cfg.Storage.Postgres.MinConns)
	if err != nil {
		return fmt.Errorf("postgres: %w", err)
	}
	defer pool.Close()
	if err := postgres.Migrate(ctx, pool); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	repo := postgres.NewProfileRepo(pool)

	stream, err := jetstream.ConnectFlows(jetstream.FlowStreamConfig{
		URL: cfg.Storage.JetStream.URL,
	})
	if err != nil {
		return fmt.Errorf("flow conveyor: %w", err)
	}
	defer stream.Close()
	logger.Info("connected to flow conveyor", "url", cfg.Storage.JetStream.URL)

	agg := profile.NewAggregator(profile.DefaultCaps(), profile.DefaultTemplateOptions())

	// Resume from what is already learned: templates and caps only stay
	// monotonic across restarts because the process reloads its own output.
	stored, err := repo.LoadAll(ctx)
	if err != nil {
		return fmt.Errorf("load stored profiles: %w", err)
	}
	agg.Load(stored)
	logger.Info("restored endpoint profiles", "count", len(stored))

	// Per-tenant policy, refreshed like logproc's filter cache — but failing
	// CLOSED: a tenant whose config never loaded is not profiled. Profiling is
	// additive, so not-analyzing is the safe degradation.
	cc := &configCache{repo: repo, logger: logger}
	cc.refresh(ctx)
	go cc.run(ctx)

	w := &worker{
		cfg:    cfg,
		agg:    agg,
		repo:   repo,
		cc:     cc,
		logger: logger,
	}

	srv := healthServer(cfg, agg, w, logger)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("health server failed", "error", err)
			stop()
		}
	}()

	// AckWait must comfortably exceed the flush interval: messages are acked
	// only after the flush that covers them has committed.
	ackWait := 4 * cfg.Profiler.FlushInterval
	if ackWait < 5*time.Minute {
		ackWait = 5 * time.Minute
	}
	sub, err := stream.PullSubscribe(cfg.Profiler.ConsumerName, ackWait)
	if err != nil {
		return fmt.Errorf("subscribe: %w", err)
	}

	w.loop(ctx, sub)

	logger.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	w.flush(shutdownCtx) // commit what the last partial interval learned
	return srv.Shutdown(shutdownCtx)
}

// flowMsg is the slice of a published flow the profiler needs. Decoding into
// this rather than the full Flow keeps the consumer robust against additive
// flow schema changes.
type flowMsg struct {
	FlowID   string    `json:"flow_id"`
	Tenant   string    `json:"tenant"`
	LastSeen time.Time `json:"last_seen"`
	Request  struct {
		Method string `json:"method"`
		Host   string `json:"host"`
		Path   string `json:"path"`
		Query  string `json:"query"`
	} `json:"request"`
	Events []struct {
		Provider string `json:"provider"`
		Response struct {
			Status int `json:"status"`
		} `json:"response"`
	} `json:"events"`
}

// worker owns the consume-observe-flush cycle. One goroutine does everything,
// which is what makes ack-after-flush simple: no message is acked before the
// flush covering it, and no lock juggling is needed to guarantee it.
type worker struct {
	cfg    *conf.Config
	agg    *profile.Aggregator
	repo   *postgres.ProfileRepo
	cc     *configCache
	logger *slog.Logger

	pending []*nats.Msg

	mu           sync.Mutex
	consumed     int64
	skipped      int64
	lastFlushErr error
	lastFlushAt  time.Time
}

func (w *worker) loop(ctx context.Context, sub *nats.Subscription) {
	ticker := time.NewTicker(w.cfg.Profiler.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.flush(ctx)
			continue
		default:
		}

		// While a flush keeps failing, stop pulling: the pending window is the
		// replay bound, and growing it during an outage helps nothing.
		if len(w.pending) >= 2*w.cfg.Profiler.MaxPendingFlows {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				w.flush(ctx)
			}
			continue
		}

		msgs, err := sub.Fetch(256, nats.MaxWait(2*time.Second))
		if err != nil {
			if errors.Is(err, nats.ErrTimeout) || errors.Is(err, context.DeadlineExceeded) {
				continue
			}
			if ctx.Err() != nil {
				return
			}
			w.logger.Error("fetch failed", "error", err)
			continue
		}
		for _, msg := range msgs {
			w.observe(msg)
		}
		if len(w.pending) >= w.cfg.Profiler.MaxPendingFlows {
			w.flush(ctx)
		}
	}
}

func (w *worker) observe(msg *nats.Msg) {
	var fm flowMsg
	if err := json.Unmarshal(msg.Data, &fm); err != nil {
		// A message that cannot decode never will; terminate it rather than
		// letting it cycle through redelivery forever.
		_ = msg.Term()
		return
	}

	cfg, ok := w.cc.configFor(fm.Tenant)
	if !ok || !cfg.MatchHost(fm.Request.Host) || cfg.ExcludedPath(fm.Request.Path) {
		_ = msg.Ack() // policy says no: done with it, nothing to replay
		w.mu.Lock()
		w.skipped++
		w.mu.Unlock()
		return
	}

	status := 0
	providers := make([]string, 0, len(fm.Events))
	for i := len(fm.Events) - 1; i >= 0; i-- {
		if status == 0 && fm.Events[i].Response.Status > 0 {
			status = fm.Events[i].Response.Status
		}
		providers = append(providers, fm.Events[i].Provider)
	}

	w.agg.Observe(profile.Observation{
		FlowID:    fm.FlowID,
		Tenant:    fm.Tenant,
		Host:      fm.Request.Host,
		Method:    fm.Request.Method,
		Path:      fm.Request.Path,
		Query:     fm.Request.Query,
		Status:    status,
		Providers: providers,
		Seen:      fm.LastSeen,
	})
	w.pending = append(w.pending, msg)
	w.mu.Lock()
	w.consumed++
	w.mu.Unlock()
}

// flush commits learned state, then acknowledges everything it covers. On
// failure nothing is acked: the messages redeliver after AckWait and the
// flow-ID dedupe absorbs the replay's effect on counters.
func (w *worker) flush(ctx context.Context) {
	dirty, retired := w.agg.Collect()
	if len(dirty) == 0 && len(retired) == 0 {
		w.ackPending()
		return
	}
	if err := w.repo.UpsertEndpoints(ctx, dirty); err != nil {
		w.flushFailed(dirty, retired, err)
		return
	}
	if err := w.repo.DeleteEndpoints(ctx, retired); err != nil {
		w.flushFailed(nil, retired, err)
		return
	}
	w.ackPending()
	w.mu.Lock()
	w.lastFlushErr = nil
	w.lastFlushAt = time.Now().UTC()
	w.mu.Unlock()
	w.logger.Info("profiles flushed", "endpoints", len(dirty), "retired", len(retired))
}

func (w *worker) flushFailed(dirty []*profile.EndpointProfile, retired []string, err error) {
	w.agg.Requeue(dirty, retired)
	w.mu.Lock()
	w.lastFlushErr = err
	w.mu.Unlock()
	w.logger.Error("profile flush failed; will retry", "error", err,
		"pending_messages", len(w.pending))
}

func (w *worker) ackPending() {
	for _, msg := range w.pending {
		_ = msg.Ack()
	}
	w.pending = w.pending[:0]
}

func (w *worker) status() (consumed, skipped int64, flushErr error, lastFlush time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.consumed, w.skipped, w.lastFlushErr, w.lastFlushAt
}

// configCache mirrors logproc's filterCache pattern, refreshing per-tenant
// policy on a 30s snapshot — but failing CLOSED (see AllConfigs).
type configCache struct {
	repo   *postgres.ProfileRepo
	logger *slog.Logger
	mu     sync.RWMutex
	cfgs   map[string]profile.TenantConfig
}

func (c *configCache) run(ctx context.Context) {
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

func (c *configCache) refresh(ctx context.Context) {
	cfgs, err := c.repo.AllConfigs(ctx)
	if err != nil {
		c.logger.Warn("profiler config refresh failed; previous snapshot keeps applying", "error", err)
		return
	}
	c.mu.Lock()
	c.cfgs = cfgs
	c.mu.Unlock()
}

func (c *configCache) configFor(tenant string) (profile.TenantConfig, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	cfg, ok := c.cfgs[tenant]
	return cfg, ok
}

// healthServer asserts semantic health (Constitution IV): the process being
// alive means nothing if flushes fail or nothing is being learned.
func healthServer(cfg *conf.Config, agg *profile.Aggregator, w *worker, logger *slog.Logger) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(rw http.ResponseWriter, r *http.Request) {
		consumed, skipped, flushErr, lastFlush := w.status()
		stats := agg.Stats()
		state := "healthy"
		flushMsg := ""
		if flushErr != nil {
			state = "degraded"
			flushMsg = flushErr.Error()
			rw.WriteHeader(http.StatusServiceUnavailable)
		}
		rw.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(rw).Encode(map[string]any{
			"status":        state,
			"consumed":      consumed,
			"skipped":       skipped,
			"last_flush_at": lastFlush,
			"flush_error":   flushMsg,
			"aggregator":    stats,
		})
	})
	logger.Info("health listening", "addr", cfg.Server.HTTPAddr)
	return &http.Server{
		Addr:         cfg.Server.HTTPAddr,
		Handler:      mux,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}
}
