//go:build load

// Package load drives the ingest path at production rates.
package load

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"math/rand"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// Harness pushes synthetic — but realistically SHAPED — records at the ingest
// endpoints. Shape matters more than volume: VictoriaMetrics' own guidance is
// to benchmark with data resembling production, because uniform synthetic
// records compress unrealistically well and overstate every throughput number.
type Harness struct {
	IngestBase string
	Secret     string
	Client     *http.Client

	sent   atomic.Int64
	failed atomic.Int64
	rng    *rand.Rand
	rngMu  sync.Mutex
}

func NewHarness(base, secret string) *Harness {
	return &Harness{
		IngestBase: base,
		Secret:     secret,
		Client:     &http.Client{Timeout: 30 * time.Second},
		//nolint:gosec // load-shape randomness, not cryptography
		rng: rand.New(rand.NewSource(42)), // fixed seed: comparable runs
	}
}

// Stats reports what the run achieved.
type Stats struct {
	Sent   int64
	Failed int64
}

func (h *Harness) Stats() Stats {
	return Stats{Sent: h.sent.Load(), Failed: h.failed.Load()}
}

// Run drives all four providers at ratePerProvider events/sec for the duration,
// batching once per second per provider — which is how the real providers
// deliver, and what exercises the batch path rather than a per-event path no
// production traffic takes.
func (h *Harness) Run(ratePerProvider int, duration time.Duration) Stats {
	var wg sync.WaitGroup
	stop := time.After(duration)
	done := make(chan struct{})
	go func() { <-stop; close(done) }()

	providers := []struct {
		endpoint string
		record   func(i int64) []byte
	}{
		{"/ingest/v1/cloudflare/logpush", h.cloudflareRecord},
		{"/ingest/v1/vector/nginx", h.nginxRecord},
		{"/ingest/v1/vector/f5asm", h.f5Record},
		{"/ingest/v1/vector/datadome", h.nginxRecord}, // shape stand-in
	}

	for _, p := range providers {
		wg.Add(1)
		go func(endpoint string, record func(int64) []byte) {
			defer wg.Done()
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-done:
					return
				case <-ticker.C:
					h.sendBatch(endpoint, record, ratePerProvider)
				}
			}
		}(p.endpoint, p.record)
	}
	wg.Wait()
	return h.Stats()
}

func (h *Harness) sendBatch(endpoint string, record func(int64) []byte, n int) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	base := h.sent.Load()
	for i := 0; i < n; i++ {
		gz.Write(record(base + int64(i)))
		gz.Write([]byte("\n"))
	}
	gz.Close()

	req, err := http.NewRequest(http.MethodPost, h.IngestBase+endpoint, &buf)
	if err != nil {
		h.failed.Add(int64(n))
		return
	}
	req.Header.Set("Authorization", "Bearer "+h.Secret)
	req.Header.Set("Content-Encoding", "gzip")

	resp, err := h.Client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		// A 503 here is the ingest endpoint refusing to lie about durability;
		// the real providers retry, and the harness counts it as failed delivery
		// so backpressure is VISIBLE in the result rather than smoothed over.
		h.failed.Add(int64(n))
		if resp != nil {
			resp.Body.Close()
		}
		return
	}
	resp.Body.Close()
	h.sent.Add(int64(n))
}

// Realistic record shapes: varying rays, hosts, paths and scores, so index
// cardinality and compression behave like production rather than like a
// thousand copies of one line.

func (h *Harness) cloudflareRecord(i int64) []byte {
	return []byte(fmt.Sprintf(
		`{"RayID":"%016x","ParentRayID":"00","EdgeStartTimestamp":"%s","ClientIP":"203.0.%d.%d",`+
			`"ClientRequestHost":"host%d.example.com","ClientRequestURI":"/path/%d?q=%d",`+
			`"ClientRequestMethod":"GET","EdgeResponseStatus":%d,"BotScore":%d,"SecurityAction":"%s"}`,
		i, time.Now().UTC().Format(time.RFC3339Nano),
		i%200, i%250, i%20, i%1000, i,
		[]int{200, 200, 200, 403, 429}[i%5], i%100,
		[]string{"", "", "", "block", ""}[i%5]))
}

func (h *Harness) nginxRecord(i int64) []byte {
	return []byte(fmt.Sprintf(
		`{"time_iso8601":"%s","cf_ray":"%016x-FRA","cf_connecting_ip":"203.0.%d.%d",`+
			`"host":"host%d.example.com","request_method":"GET","request_uri":"/path/%d",`+
			`"status":%d,"body_bytes_sent":%d,"request_time":0.0%d}`,
		time.Now().Format(time.RFC3339), i, i%200, i%250, i%20, i%1000,
		[]int{200, 200, 200, 403, 500}[i%5], 100+i%9000, 1+i%9))
}

func (h *Harness) f5Record(i int64) []byte {
	return []byte(fmt.Sprintf(
		`support_id="%d",policy_name="/Common/p",violations="N/A",request_status="passed",`+
			`response_code="200",ip_client="203.0.%d.%d",method="GET",date_time="%s",`+
			`attack_type="N/A",uri="/path/%d",request="GET /path/%d HTTP/1.1\r\nCF-Ray: %016x\r\n\r\n"`,
		1000000000000000+i, i%200, i%250,
		time.Now().UTC().Format("2006-01-02 15:04:05"), i%1000, i%1000, i))
}
