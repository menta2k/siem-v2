// Package valkey holds Valkey-backed adapters.
package valkey

import (
	"context"
	"fmt"
	"time"

	valkeygo "github.com/valkey-io/valkey-go"
)

// Revocations records logged-out refresh tokens.
//
// Only refresh tokens are tracked. Access tokens are deliberately not
// revocable: doing so would put a cache read on every authenticated request,
// and their lifetime is already short enough that the exposure window is
// bounded. Logout invalidates the refresh token, so the session cannot be
// extended past the current access token.
//
// Entries expire with the token itself. A revocation list that outlives the
// tokens it names grows without bound and never rejects anything a signature
// check would not have rejected anyway.
type Revocations struct {
	client valkeygo.Client
}

func NewRevocations(client valkeygo.Client) *Revocations {
	return &Revocations{client: client}
}

func revocationKey(tokenID string) string { return "auth:revoked:" + tokenID }

// Revoke marks a token id unusable for ttl.
func (r *Revocations) Revoke(ctx context.Context, tokenID string, ttl time.Duration) error {
	if tokenID == "" {
		return fmt.Errorf("auth: cannot revoke an empty token id")
	}
	if ttl <= 0 {
		ttl = 7 * 24 * time.Hour
	}
	cmd := r.client.B().Set().Key(revocationKey(tokenID)).Value("1").
		Ex(ttl).Build()
	if err := r.client.Do(ctx, cmd).Error(); err != nil {
		return fmt.Errorf("record revocation: %w", err)
	}
	return nil
}

// IsRevoked reports whether a token id has been revoked.
func (r *Revocations) IsRevoked(ctx context.Context, tokenID string) (bool, error) {
	cmd := r.client.B().Exists().Key(revocationKey(tokenID)).Build()
	n, err := r.client.Do(ctx, cmd).AsInt64()
	if err != nil {
		// The caller fails closed on this error; returning false here instead
		// would quietly honour a possibly-revoked token whenever the cache is
		// down.
		return false, fmt.Errorf("check revocation: %w", err)
	}
	return n > 0, nil
}
