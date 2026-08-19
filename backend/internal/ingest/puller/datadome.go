// Package puller polls provider export APIs for sources that cannot push.
//
// DataDome is the only pull-mode source. Its webhook carries attack summaries
// with no per-request identifier, so it cannot feed correlation at all; the log
// export API is the only viable path (research.md R3).
package puller

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/menta2k/siem-v2/backend/internal/ingest"
	"github.com/menta2k/siem-v2/backend/internal/normalize/schema"
)

// Watermark records how far a puller has read.
//
// It is what makes a restart safe: without it, a puller either re-reads its last
// window (duplicating work) or skips it (losing data silently, which is worse).
type Watermark struct {
	SourceID string
	Position time.Time
}

// WatermarkStore persists per-source read positions.
type WatermarkStore interface {
	Get(ctx context.Context, sourceID string) (Watermark, error)
	Set(ctx context.Context, wm Watermark) error
}

// DataDomePuller polls the DataDome log export API.
type DataDomePuller struct {
	Client     *http.Client
	Endpoint   string
	APIKey     string
	Tenant     string
	SourceID   string
	Buffer     ingest.Buffer
	Watermarks WatermarkStore
	// Window bounds a single poll's time range so a long outage does not produce
	// one enormous request that times out and can never succeed.
	Window time.Duration
	Now    func() time.Time
}

func (p *DataDomePuller) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now().UTC()
}

func (p *DataDomePuller) window() time.Duration {
	if p.Window > 0 {
		return p.Window
	}
	return 5 * time.Minute
}

// Poll performs one collection cycle and returns how many records were buffered.
//
// The watermark advances only AFTER the batch is durably buffered. That ordering
// is the whole safety property: a crash between fetch and buffer re-reads the
// window, and the resulting duplicates collapse via deterministic record ids.
// Advancing first would skip the window permanently.
func (p *DataDomePuller) Poll(ctx context.Context) (int, error) {
	wm, err := p.Watermarks.Get(ctx, p.SourceID)
	if err != nil {
		return 0, fmt.Errorf("read watermark: %w", err)
	}

	from := wm.Position
	if from.IsZero() {
		// First run: start one window back rather than at the epoch, which would
		// request the provider's entire history.
		from = p.now().Add(-p.window())
	}
	to := from.Add(p.window())
	if now := p.now(); to.After(now) {
		to = now
	}
	if !to.After(from) {
		return 0, nil // nothing new to read yet
	}

	records, err := p.fetch(ctx, from, to)
	if err != nil {
		return 0, err
	}
	if len(records) == 0 {
		// An empty window still advances the watermark: the time range was read
		// successfully and there was simply nothing in it.
		return 0, p.Watermarks.Set(ctx, Watermark{SourceID: p.SourceID, Position: to})
	}

	batch := ingest.RawBatch{
		BatchID:    fmt.Sprintf("dd:%d-%d", from.Unix(), to.Unix()),
		SourceID:   p.SourceID,
		Tenant:     p.Tenant,
		Provider:   schema.ProviderDataDome,
		ReceivedAt: p.now(),
		Records:    records,
	}
	if err := p.Buffer.Append(ctx, batch); err != nil {
		// Watermark deliberately NOT advanced: the window will be re-read.
		return 0, fmt.Errorf("buffer batch: %w", err)
	}

	if err := p.Watermarks.Set(ctx, Watermark{SourceID: p.SourceID, Position: to}); err != nil {
		return len(records), fmt.Errorf("advance watermark: %w", err)
	}
	return len(records), nil
}

func (p *DataDomePuller) fetch(ctx context.Context, from, to time.Time) ([][]byte, error) {
	u, err := url.Parse(p.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid endpoint: %w", err)
	}
	u.Path = "/v1/logs/export"
	q := u.Query()
	q.Set("from", from.UTC().Format(time.RFC3339))
	q.Set("to", to.UTC().Format(time.RFC3339))
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Api-Key", p.APIKey)
	req.Header.Set("Accept", "application/json")

	client := p.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("datadome export request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
		// Worth distinguishing: log export is generally a Corporate/Enterprise
		// feature, so this is usually an entitlement problem rather than a bad key
		// (verification item V10).
		return nil, fmt.Errorf("datadome export returned %d: check the API key and that "+
			"the account's plan includes log export", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("datadome export returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var items []json.RawMessage
	if err := json.Unmarshal(body, &items); err != nil {
		return nil, fmt.Errorf("decode export payload: %w", err)
	}
	out := make([][]byte, 0, len(items))
	for _, item := range items {
		rec, _ := ingest.TruncateRecord(item)
		cp := make([]byte, len(rec))
		copy(cp, rec)
		out = append(out, cp)
	}
	return out, nil
}

// MemoryWatermarks is an in-memory WatermarkStore for tests.
type MemoryWatermarks struct {
	positions map[string]time.Time
}

func NewMemoryWatermarks() *MemoryWatermarks {
	return &MemoryWatermarks{positions: map[string]time.Time{}}
}

func (m *MemoryWatermarks) Get(_ context.Context, sourceID string) (Watermark, error) {
	return Watermark{SourceID: sourceID, Position: m.positions[sourceID]}, nil
}

func (m *MemoryWatermarks) Set(_ context.Context, wm Watermark) error {
	m.positions[wm.SourceID] = wm.Position
	return nil
}
