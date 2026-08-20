package valkey

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/menta2k/siem-v2/backend/internal/correlate/window"
	valkeygo "github.com/valkey-io/valkey-go"
)

// Snapshot is the full correlation state persisted across restart: the
// in-flight window plus the merge index that reunites late stragglers with
// their already-stored partners.
type Snapshot struct {
	Window     []*window.State      `json:"window"`
	RecentKeys map[string]time.Time `json:"recent_keys"`
}

// CorrelationState persists the in-flight correlation window across restarts.
//
// FR-023: a restart must RESUME partial flows, not discard them. Without this
// a deploy silently drops every flow whose window was still open — including,
// once, a manually-triggered SQLi block an operator was watching for.
type CorrelationState struct {
	client valkeygo.Client
	key    string
}

func NewCorrelationState(client valkeygo.Client) *CorrelationState {
	return &CorrelationState{client: client, key: "siem:correlation:window"}
}

// Save writes the whole in-flight snapshot as one value. The window is bounded
// by the late-arrival horizon, so this stays small — thousands of states, not
// millions.
func (c *CorrelationState) Save(ctx context.Context, snap Snapshot) error {
	payload, err := json.Marshal(snap)
	if err != nil {
		return fmt.Errorf("encode correlation snapshot: %w", err)
	}
	cmd := c.client.B().Set().Key(c.key).Value(string(payload)).Build()
	if err := c.client.Do(ctx, cmd).Error(); err != nil {
		return fmt.Errorf("save correlation window: %w", err)
	}
	return nil
}

// Load reads the snapshot; a missing key returns an empty snapshot (first boot).
func (c *CorrelationState) Load(ctx context.Context) (Snapshot, error) {
	raw, err := c.client.Do(ctx, c.client.B().Get().Key(c.key).Build()).ToString()
	if err != nil {
		if valkeygo.IsValkeyNil(err) {
			return Snapshot{}, nil
		}
		return Snapshot{}, fmt.Errorf("load correlation snapshot: %w", err)
	}
	var snap Snapshot
	if err := json.Unmarshal([]byte(raw), &snap); err != nil {
		return Snapshot{}, fmt.Errorf("decode correlation snapshot: %w", err)
	}
	return snap, nil
}

// Clear removes the snapshot after a successful restore, so a later crash
// cannot replay a stale window on top of live state.
func (c *CorrelationState) Clear(ctx context.Context) error {
	return c.client.Do(ctx, c.client.B().Del().Key(c.key).Build()).Error()
}
