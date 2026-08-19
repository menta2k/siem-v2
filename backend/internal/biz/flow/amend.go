package flow

import (
	"context"
	"fmt"
	"time"

	"github.com/menta2k/siem-v2/backend/internal/correlate"
	"github.com/menta2k/siem-v2/backend/internal/normalize/schema"
)

// Amender updates a stored flow when a record arrives after it closed.
//
// Showing an analyst two flows for one request is worse than showing one
// late-corrected flow, so a very late record amends in place. The amendment is
// marked rather than hidden: a flow that changed after someone looked at it is
// something they need to know (FR-018).
type Amender struct {
	Store  Store
	Loader FlowLoader
	Now    func() time.Time
}

// FlowLoader fetches a stored flow for amendment.
type FlowLoader interface {
	Get(ctx context.Context, tenantID, flowID string) (*Flow, error)
}

// Amend adds a late event to an existing flow and re-materializes it.
//
// Returns nil when there is no such flow — the caller should then treat the
// record as opening a new one rather than silently dropping it.
func (a *Amender) Amend(ctx context.Context, tenantID, correlationKey string, late schema.Event) (*Flow, error) {
	flowID := flowID(correlationKey)

	existing, err := a.Loader.Get(ctx, tenantID, flowID)
	if err != nil {
		return nil, fmt.Errorf("load flow for amendment: %w", err)
	}
	if existing == nil {
		return nil, nil
	}

	// Idempotent: a redelivered late record must not add a second copy of a
	// layer that is already present (FR-007).
	for _, e := range existing.Events {
		if e.EventID == late.EventID {
			return existing, nil
		}
	}

	events := append(append([]schema.Event{}, existing.Events...), late)
	amended := Materialize(correlationKey, events, Options{
		Tenant:  existing.Tenant,
		Method:  existing.Method,
		Bridged: existing.Bridged,
		Closed:  true,
		Now:     a.now(),
	})
	if amended == nil {
		return nil, fmt.Errorf("re-materializing flow %s produced nothing", flowID)
	}

	// The amendment flag survives re-materialization: it describes the flow's
	// history, not its current contents.
	amended.Amended = true
	amended.ClosedAt = existing.ClosedAt

	if skewed, _ := correlate.DetectSkew(amended.Events); skewed {
		amended.addFlag(schema.FlagClockSkew)
	}

	if err := a.Store.Store(ctx, amended); err != nil {
		return nil, fmt.Errorf("store amended flow: %w", err)
	}
	return amended, nil
}

func (a *Amender) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now().UTC()
}
