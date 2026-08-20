package valkey

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/menta2k/siem-v2/backend/internal/correlate/window"
	valkeygo "github.com/valkey-io/valkey-go"
)

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
func (c *CorrelationState) Save(ctx context.Context, states []*window.State) error {
	payload, err := json.Marshal(states)
	if err != nil {
		return fmt.Errorf("encode correlation window: %w", err)
	}
	cmd := c.client.B().Set().Key(c.key).Value(string(payload)).Build()
	if err := c.client.Do(ctx, cmd).Error(); err != nil {
		return fmt.Errorf("save correlation window: %w", err)
	}
	return nil
}

// Load reads the snapshot; a missing key returns nil, nil (first boot).
func (c *CorrelationState) Load(ctx context.Context) ([]*window.State, error) {
	raw, err := c.client.Do(ctx, c.client.B().Get().Key(c.key).Build()).ToString()
	if err != nil {
		if valkeygo.IsValkeyNil(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("load correlation window: %w", err)
	}
	var states []*window.State
	if err := json.Unmarshal([]byte(raw), &states); err != nil {
		return nil, fmt.Errorf("decode correlation window: %w", err)
	}
	return states, nil
}

// Clear removes the snapshot after a successful restore, so a later crash
// cannot replay a stale window on top of live state.
func (c *CorrelationState) Clear(ctx context.Context) error {
	return c.client.Do(ctx, c.client.B().Del().Key(c.key).Build()).Error()
}
