package alerting

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// Destination delivers an alert somewhere an operator will see it.
type Destination interface {
	Name() string
	Deliver(ctx context.Context, a Alert) error
}

// DeliveryState records what happened to an alert.
type DeliveryState string

const (
	DeliveryPending   DeliveryState = "pending"
	DeliveryDelivered DeliveryState = "delivered"
	DeliveryFailed    DeliveryState = "failed"
)

// Dispatcher sends alerts to every configured destination.
//
// It watches its own delivery health, because a SIEM whose alerts silently stop
// arriving is in exactly the state Principle IV exists to prevent — everything
// looks fine, and nothing is being told to anyone (FR-050).
type Dispatcher struct {
	Destinations []Destination
	// FailureThreshold is the number of consecutive failures after which a
	// destination is itself considered an incident.
	FailureThreshold int
	Now              func() time.Time

	mu       sync.Mutex
	failures map[string]int
	lastOK   map[string]time.Time
}

func NewDispatcher(dests ...Destination) *Dispatcher {
	return &Dispatcher{
		Destinations:     dests,
		FailureThreshold: 3,
		Now:              func() time.Time { return time.Now().UTC() },
		failures:         map[string]int{},
		lastOK:           map[string]time.Time{},
	}
}

// Dispatch delivers to every destination, returning the states observed.
//
// One failing destination must not stop the others: an alert reaching Slack but
// not PagerDuty is far better than an alert reaching nobody because the first
// attempt errored.
func (d *Dispatcher) Dispatch(ctx context.Context, a Alert) map[string]DeliveryState {
	states := make(map[string]DeliveryState, len(d.Destinations))
	for _, dest := range d.Destinations {
		if err := dest.Deliver(ctx, a); err != nil {
			states[dest.Name()] = DeliveryFailed
			d.recordFailure(dest.Name())
			continue
		}
		states[dest.Name()] = DeliveryDelivered
		d.recordSuccess(dest.Name())
	}
	return states
}

func (d *Dispatcher) recordFailure(name string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.failures[name]++
}

func (d *Dispatcher) recordSuccess(name string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.failures[name] = 0
	d.lastOK[name] = d.Now()
}

// UnhealthyDestinations returns destinations failing past the threshold.
//
// This is the "who watches the watchmen" case: an operator must be told when the
// alerting path itself is broken, and that news cannot travel by the same broken
// path (FR-050).
func (d *Dispatcher) UnhealthyDestinations() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []string
	for name, count := range d.failures {
		if count >= d.FailureThreshold {
			out = append(out, name)
		}
	}
	return out
}

// WebhookDestination posts alerts as JSON.
type WebhookDestination struct {
	DestName string
	URL      string
	Client   *http.Client
	Timeout  time.Duration
}

func (w *WebhookDestination) Name() string {
	if w.DestName != "" {
		return w.DestName
	}
	return "webhook"
}

func (w *WebhookDestination) Deliver(ctx context.Context, a Alert) error {
	body, err := json.Marshal(a)
	if err != nil {
		return fmt.Errorf("encode alert: %w", err)
	}

	timeout := w.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	client := w.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("deliver to %s: %w", w.Name(), err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("destination %s returned %d", w.Name(), resp.StatusCode)
	}
	return nil
}

// LogDestination writes alerts to the service log. It exists so that a
// deployment with no destinations configured still records alerts somewhere
// rather than discarding them.
type LogDestination struct {
	Sink func(Alert)
}

func (l *LogDestination) Name() string { return "log" }

func (l *LogDestination) Deliver(_ context.Context, a Alert) error {
	if l.Sink != nil {
		l.Sink(a)
	}
	return nil
}
