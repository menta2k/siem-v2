//go:build load

package load

import (
	"flag"
	"os"
	"testing"
	"time"
)

var (
	rate      = flag.Int("rate", 2000, "events per second per provider")
	duration  = flag.Duration("duration", time.Minute, "run length")
	ingestURL = flag.String("ingest", "http://localhost:8100", "ingest base URL")
)

// TestBurstLoad drives all four providers at the configured rate and asserts
// ZERO delivery failure — the ingest endpoint may slow down, but a 503 means a
// real provider would be retrying, and sustained 503s at the target rate mean
// SC-004/SC-005 do not hold.
func TestBurstLoad(t *testing.T) {
	secret := os.Getenv("SIEM_INGEST_SECRET")
	if secret == "" {
		t.Skip("SIEM_INGEST_SECRET not set; harness needs the live ingest endpoint")
	}

	h := NewHarness(*ingestURL, secret)
	start := time.Now()
	stats := h.Run(*rate, *duration)
	elapsed := time.Since(start)

	perSecond := float64(stats.Sent) / elapsed.Seconds()
	t.Logf("sent=%d failed=%d over %s (%.0f events/sec aggregate, target %d)",
		stats.Sent, stats.Failed, elapsed.Round(time.Second), perSecond, *rate*4)

	if stats.Failed > 0 {
		t.Errorf("%d events were refused; the durable buffer could not keep up at this rate", stats.Failed)
	}
	if stats.Sent == 0 {
		t.Fatal("nothing was delivered; is logproc running?")
	}
}
