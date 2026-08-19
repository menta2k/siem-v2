package asnowner

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// DefaultSourceURL is iptoasn.com's combined v4+v6 snapshot (v1's source).
const DefaultSourceURL = "https://iptoasn.com/data/ip2asn-combined.tsv.gz"

// DefaultInterval: registry attribution changes on timescales of weeks; daily
// is already generous.
const DefaultInterval = 24 * time.Hour

// DefaultTimeout bounds one download+parse+store cycle.
const DefaultTimeout = 2 * time.Minute

// Storer persists a parsed snapshot — implemented by the postgres repo.
type Storer interface {
	Replace(ctx context.Context, owners []Owner) error
}

// Worker downloads and stores the attribution snapshot on an interval.
//
// Failures are WARN-and-keep-going: the previous snapshot stays serving, and
// bare AS numbers are a cosmetic regression, never an outage. The worker is
// deliberately not leader-elected (v1 decision) — concurrent refreshes write
// identical rows and the upsert makes the race harmless.
type Worker struct {
	Source   Storer
	URL      string
	Interval time.Duration
	Timeout  time.Duration
	Client   *http.Client
	Logger   *slog.Logger
}

func (w *Worker) url() string {
	if w.URL != "" {
		return w.URL
	}
	return DefaultSourceURL
}

// Run refreshes once immediately, then on the interval, until ctx ends.
func (w *Worker) Run(ctx context.Context) {
	interval := w.Interval
	if interval <= 0 {
		interval = DefaultInterval
	}
	w.refreshOnce(ctx)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.refreshOnce(ctx)
		}
	}
}

func (w *Worker) refreshOnce(ctx context.Context) {
	if err := w.Refresh(ctx); err != nil && w.Logger != nil {
		w.Logger.Warn("asn owner refresh failed; previous names keep serving", "error", err)
	}
}

// Refresh performs one download-parse-store cycle.
func (w *Worker) Refresh(ctx context.Context) error {
	// HTTPS only: this table decorates security dashboards, and a plaintext
	// fetch would let a network position rewrite attributions at will.
	if !strings.HasPrefix(w.url(), "https://") {
		return fmt.Errorf("asnowner: source must be https, got %q", w.url())
	}
	timeout := w.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, w.url(), nil)
	if err != nil {
		return fmt.Errorf("asnowner: build request: %w", err)
	}
	client := w.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("asnowner: download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("asnowner: download: status %d", resp.StatusCode)
	}

	owners, err := ParseGzip(resp.Body)
	if err != nil {
		return err
	}
	if err := w.Source.Replace(ctx, owners); err != nil {
		return err
	}
	if w.Logger != nil {
		w.Logger.Info("asn owner snapshot refreshed", "owners", len(owners))
	}
	return nil
}
