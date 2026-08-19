package alerting

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type flakyDest struct {
	name string
	err  error
	got  []Alert
}

func (f *flakyDest) Name() string { return f.name }
func (f *flakyDest) Deliver(_ context.Context, a Alert) error {
	if f.err != nil {
		return f.err
	}
	f.got = append(f.got, a)
	return nil
}

func sampleAlert() Alert {
	return Alert{AlertID: "alert:1", DetectionID: "pipeline.test", Severity: SeverityHigh}
}

// TestOneFailingDestinationDoesNotBlockOthers: an alert reaching one channel
// beats an alert reaching none.
func TestOneFailingDestinationDoesNotBlockOthers(t *testing.T) {
	broken := &flakyDest{name: "pagerduty", err: errors.New("503")}
	working := &flakyDest{name: "slack"}
	d := NewDispatcher(broken, working)

	states := d.Dispatch(context.Background(), sampleAlert())
	if states["pagerduty"] != DeliveryFailed {
		t.Errorf("failing destination should report failure, got %q", states["pagerduty"])
	}
	if states["slack"] != DeliveryDelivered {
		t.Errorf("the working destination must still receive the alert, got %q", states["slack"])
	}
	if len(working.got) != 1 {
		t.Error("the alert did not reach the working destination")
	}
}

// TestBrokenDeliveryPathBecomesItsOwnIncident is the who-watches-the-watchmen
// case: alerts silently failing to arrive is the exact state Principle IV exists
// to prevent.
func TestBrokenDeliveryPathBecomesItsOwnIncident(t *testing.T) {
	broken := &flakyDest{name: "pagerduty", err: errors.New("503")}
	d := NewDispatcher(broken)
	d.FailureThreshold = 3

	for i := 0; i < 2; i++ {
		d.Dispatch(context.Background(), sampleAlert())
	}
	if len(d.UnhealthyDestinations()) != 0 {
		t.Fatal("two failures is a blip, not yet an incident")
	}

	d.Dispatch(context.Background(), sampleAlert())
	unhealthy := d.UnhealthyDestinations()
	if len(unhealthy) != 1 || unhealthy[0] != "pagerduty" {
		t.Fatalf("a persistently failing destination must be reported, got %v", unhealthy)
	}
}

func TestRecoveryClearsFailureCount(t *testing.T) {
	dest := &flakyDest{name: "slack", err: errors.New("down")}
	d := NewDispatcher(dest)
	d.FailureThreshold = 2

	d.Dispatch(context.Background(), sampleAlert())
	d.Dispatch(context.Background(), sampleAlert())
	if len(d.UnhealthyDestinations()) != 1 {
		t.Fatal("expected the destination to be unhealthy")
	}

	dest.err = nil
	d.Dispatch(context.Background(), sampleAlert())
	if len(d.UnhealthyDestinations()) != 0 {
		t.Error("a successful delivery must clear the failure count")
	}
}

func TestWebhookDelivery(t *testing.T) {
	var received bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = true
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("unexpected content type: %s", r.Header.Get("Content-Type"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	dest := &WebhookDestination{DestName: "hook", URL: srv.URL, Client: srv.Client()}
	if err := dest.Deliver(context.Background(), sampleAlert()); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	if !received {
		t.Error("the webhook was not called")
	}
}

func TestWebhookNon2xxIsAFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	dest := &WebhookDestination{DestName: "hook", URL: srv.URL, Client: srv.Client()}
	if err := dest.Deliver(context.Background(), sampleAlert()); err == nil {
		t.Fatal("a 500 from the destination must count as a delivery failure")
	}
}

func TestWebhookTimeoutIsBounded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
	}))
	defer srv.Close()

	dest := &WebhookDestination{DestName: "slow", URL: srv.URL, Client: srv.Client(), Timeout: 50 * time.Millisecond}
	if err := dest.Deliver(context.Background(), sampleAlert()); err == nil {
		t.Fatal("a hanging destination must not block alerting indefinitely")
	}
}

// TestLogDestinationCatchesUnconfiguredDeployments: with no destinations set up,
// alerts must still land somewhere rather than being discarded.
func TestLogDestinationCatchesUnconfiguredDeployments(t *testing.T) {
	var logged []Alert
	d := NewDispatcher(&LogDestination{Sink: func(a Alert) { logged = append(logged, a) }})
	d.Dispatch(context.Background(), sampleAlert())
	if len(logged) != 1 {
		t.Fatal("an alert must never be silently discarded")
	}
}
