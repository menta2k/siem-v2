package observability

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Recovery is a bounded, automatic repair for a known-recoverable condition.
//
// Constitution Principle IV permits self-healing only where it is "safe and
// deterministic", and requires every attempt to be logged with its cause and
// outcome. The bounds here are what keep it from becoming a restart loop that
// hides a real fault: a component that keeps failing must eventually stop being
// quietly restarted and start being reported.
type Recovery struct {
	Name string
	// Attempt performs the repair. It must be idempotent: it may run again after
	// a partial success.
	Attempt func(context.Context) error
	// MaxAttempts bounds how many times this is tried within the window. Beyond
	// it, the condition is escalated rather than retried — a fault that survives
	// repeated recovery is not the kind of fault recovery fixes.
	MaxAttempts int
	// Backoff between attempts.
	Backoff time.Duration
	// Window after which the attempt count resets.
	Window time.Duration
}

// RecoveryOutcome records what happened, for the log and for the operator.
type RecoveryOutcome struct {
	Name      string
	Cause     string
	Attempt   int
	Succeeded bool
	Err       error
	At        time.Time
	// Escalated is true when recovery gave up. This is the important case: it
	// means the problem needs a human, and silently continuing to retry would
	// hide that.
	Escalated bool
}

// Healer runs bounded recoveries and reports every attempt.
type Healer struct {
	mu       sync.Mutex
	attempts map[string]int
	lastTry  map[string]time.Time
	Now      func() time.Time
	// OnOutcome receives every attempt. Constitution IV requires each to be
	// logged with cause and outcome, so this is not optional in practice.
	OnOutcome func(RecoveryOutcome)
}

func NewHealer() *Healer {
	return &Healer{
		attempts: map[string]int{},
		lastTry:  map[string]time.Time{},
		Now:      func() time.Time { return time.Now().UTC() },
	}
}

// Heal attempts a recovery, respecting its bounds.
//
// Returns true when the condition was repaired. A false return with Escalated
// set means recovery is exhausted and the condition needs reporting.
func (h *Healer) Heal(ctx context.Context, r Recovery, cause string) RecoveryOutcome {
	h.mu.Lock()
	now := h.Now()
	if last, seen := h.lastTry[r.Name]; seen && r.Window > 0 && now.Sub(last) > r.Window {
		// Long enough since the last attempt that this is a new incident, not a
		// continuation of the old one.
		h.attempts[r.Name] = 0
	}
	h.attempts[r.Name]++
	attempt := h.attempts[r.Name]
	h.lastTry[r.Name] = now
	h.mu.Unlock()

	outcome := RecoveryOutcome{Name: r.Name, Cause: cause, Attempt: attempt, At: now}

	maxAttempts := r.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = 3
	}
	if attempt > maxAttempts {
		outcome.Escalated = true
		outcome.Err = fmt.Errorf("recovery %q exhausted after %d attempts; the condition needs a human",
			r.Name, maxAttempts)
		h.report(outcome)
		return outcome
	}

	if r.Attempt == nil {
		outcome.Err = fmt.Errorf("recovery %q has no attempt function", r.Name)
		h.report(outcome)
		return outcome
	}

	if err := r.Attempt(ctx); err != nil {
		outcome.Err = err
		h.report(outcome)
		return outcome
	}

	outcome.Succeeded = true
	h.mu.Lock()
	// A success resets the count, so an intermittent fault does not accumulate
	// toward escalation over hours.
	h.attempts[r.Name] = 0
	h.mu.Unlock()
	h.report(outcome)
	return outcome
}

func (h *Healer) report(o RecoveryOutcome) {
	if h.OnOutcome != nil {
		h.OnOutcome(o)
	}
}

// Attempts reports how many consecutive attempts a recovery has made.
func (h *Healer) Attempts(name string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.attempts[name]
}
