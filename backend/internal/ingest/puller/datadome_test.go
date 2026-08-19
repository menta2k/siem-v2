package puller

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/menta2k/siem-v2/backend/internal/ingest"
)

var start = time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)

func newPuller(t *testing.T, handler http.HandlerFunc, buf ingest.Buffer) (*DataDomePuller, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return &DataDomePuller{
		Client: srv.Client(), Endpoint: srv.URL, APIKey: "dd-key",
		Tenant: "acme", SourceID: "dd-feed-1", Buffer: buf,
		Watermarks: NewMemoryWatermarks(), Window: 5 * time.Minute,
		Now: func() time.Time { return start },
	}, srv
}

func TestPollBuffersRecordsAndAdvancesWatermark(t *testing.T) {
	buf := &ingest.MemoryBuffer{}
	p, _ := newPuller(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") != "dd-key" {
			t.Errorf("api key not sent")
		}
		if r.URL.Query().Get("from") == "" || r.URL.Query().Get("to") == "" {
			t.Errorf("time window must be sent: %s", r.URL.RawQuery)
		}
		w.Write([]byte(`[{"requestid":"a","action":"block"},{"requestid":"b","action":"allow"}]`))
	}, buf)

	n, err := p.Poll(context.Background())
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2 records, got %d", n)
	}
	if buf.RecordCount() != 2 {
		t.Errorf("records must reach the buffer, got %d", buf.RecordCount())
	}
	wm, _ := p.Watermarks.Get(context.Background(), "dd-feed-1")
	if wm.Position.IsZero() {
		t.Error("watermark must advance after a successful poll")
	}
}

// TestWatermarkNotAdvancedOnBufferFailure is the safety property that makes a
// restart survivable: re-reading a window is recoverable, skipping one is not.
func TestWatermarkNotAdvancedOnBufferFailure(t *testing.T) {
	p, _ := newPuller(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{"requestid":"a","action":"block"}]`))
	}, failingBuffer{})

	if _, err := p.Poll(context.Background()); err == nil {
		t.Fatal("a buffer failure must surface as an error")
	}
	wm, _ := p.Watermarks.Get(context.Background(), "dd-feed-1")
	if !wm.Position.IsZero() {
		t.Fatal("the watermark must NOT advance past data we failed to buffer; " +
			"advancing here would skip the window permanently")
	}
}

func TestPollResumesFromWatermarkRatherThanRereading(t *testing.T) {
	var windows []string
	buf := &ingest.MemoryBuffer{}
	p, _ := newPuller(t, func(w http.ResponseWriter, r *http.Request) {
		windows = append(windows, r.URL.Query().Get("from"))
		w.Write([]byte(`[{"requestid":"a"}]`))
	}, buf)

	if _, err := p.Poll(context.Background()); err != nil {
		t.Fatalf("first poll: %v", err)
	}
	// Advance the clock so a second window exists.
	p.Now = func() time.Time { return start.Add(10 * time.Minute) }
	if _, err := p.Poll(context.Background()); err != nil {
		t.Fatalf("second poll: %v", err)
	}

	if len(windows) != 2 {
		t.Fatalf("expected two fetches, got %d", len(windows))
	}
	if windows[0] == windows[1] {
		t.Error("the second poll must start where the first stopped, not re-read the same window")
	}
}

func TestEmptyWindowStillAdvances(t *testing.T) {
	buf := &ingest.MemoryBuffer{}
	p, _ := newPuller(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[]`))
	}, buf)

	if _, err := p.Poll(context.Background()); err != nil {
		t.Fatalf("poll: %v", err)
	}
	wm, _ := p.Watermarks.Get(context.Background(), "dd-feed-1")
	if wm.Position.IsZero() {
		t.Error("an empty window was still read successfully and must not be re-read forever")
	}
}

// TestEntitlementFailureIsDistinguishable: log export is generally an
// Enterprise feature, and "your plan does not include this" is a very different
// operator action from "your key is wrong" (V10).
func TestEntitlementFailureIsDistinguishable(t *testing.T) {
	p, _ := newPuller(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}, &ingest.MemoryBuffer{})

	_, err := p.Poll(context.Background())
	if err == nil {
		t.Fatal("a 403 must surface as an error")
	}
	if !contains(err.Error(), "log export") {
		t.Errorf("the error should point at the likely cause, got: %v", err)
	}
}

func TestFirstRunDoesNotRequestEntireHistory(t *testing.T) {
	var from string
	p, _ := newPuller(t, func(w http.ResponseWriter, r *http.Request) {
		from = r.URL.Query().Get("from")
		w.Write([]byte(`[]`))
	}, &ingest.MemoryBuffer{})

	if _, err := p.Poll(context.Background()); err != nil {
		t.Fatalf("poll: %v", err)
	}
	parsed, err := time.Parse(time.RFC3339, from)
	if err != nil {
		t.Fatalf("parse from: %v", err)
	}
	if start.Sub(parsed) > time.Hour {
		t.Errorf("first run should start one window back, not at the epoch; got %s", from)
	}
}

func TestMalformedPayloadRejected(t *testing.T) {
	p, _ := newPuller(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`not json`))
	}, &ingest.MemoryBuffer{})
	if _, err := p.Poll(context.Background()); err == nil {
		t.Fatal("an undecodable payload must not silently advance the watermark")
	}
}

type failingBuffer struct{}

func (failingBuffer) Append(context.Context, ingest.RawBatch) error {
	return errors.New("buffer down")
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
