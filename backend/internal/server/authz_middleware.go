// Package server holds HTTP wiring shared by the services.
package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/menta2k/siem-v2/backend/internal/biz/tenancy"
	apierrors "github.com/menta2k/siem-v2/backend/internal/errors"
)

// PrincipalResolver turns a presented credential into a principal.
type PrincipalResolver interface {
	ByIdentity(ctx interface{ Done() <-chan struct{} }, identity string) (*tenancy.Principal, error)
}

// Auditor records access attempts.
type Auditor interface {
	Record(tenantID, principalID, action, scope, target, outcome string, detail map[string]any)
}

// Authenticator resolves the caller and attaches the principal to the request
// context.
//
// Every request passes through this, including ones that will later be refused:
// FR-055 requires the refused attempts to be audited too, and that is only
// possible if we know who made them.
type Authenticator struct {
	Resolve func(r *http.Request) (*tenancy.Principal, error)
	Audit   Auditor
	Logger  *slog.Logger
}

// Middleware wraps a handler with authentication.
func (a *Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, err := a.Resolve(r)
		if err != nil || principal == nil {
			if a.Audit != nil {
				a.Audit.Record("", identityHint(r), "auth.failed", "", r.URL.Path, "denied",
					map[string]any{"reason": "unresolved credential"})
			}
			writeAuthError(w, apierrors.Unauthorized("credential did not resolve to an active principal"))
			return
		}
		next.ServeHTTP(w, r.WithContext(tenancy.WithPrincipal(r.Context(), principal)))
	})
}

// RequirePermission refuses a request unless the principal holds the permission,
// auditing the attempt either way.
func RequirePermission(perm tenancy.Permission, audit Auditor, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, err := tenancy.Require(r.Context(), perm)
		if err != nil {
			// An audit entry for the refusal matters as much as one for success:
			// repeated refusals are themselves a signal.
			if audit != nil {
				tenantID, principalID := "", ""
				if known, ferr := tenancy.FromContext(r.Context()); ferr == nil {
					tenantID, principalID = known.TenantID, known.ID
				}
				audit.Record(tenantID, principalID, string(perm), "", r.URL.Path, "denied",
					map[string]any{"reason": err.Error()})
			}
			// Forbidden renders as "Not found", so a caller cannot map what exists
			// by probing which error they receive.
			writeAuthError(w, apierrors.Forbidden(err.Error()))
			return
		}
		if audit != nil {
			audit.Record(p.TenantID, p.ID, string(perm), "tenant:"+p.TenantID, r.URL.Path, "allowed", nil)
		}
		next(w, r)
	}
}

func identityHint(r *http.Request) string {
	// Only enough to correlate repeated failures; never the credential itself.
	h := r.Header.Get("Authorization")
	if i := strings.IndexByte(h, ' '); i > 0 && len(h) > i+9 {
		return "presented:" + h[i+1:i+9] + "..."
	}
	return "presented:unknown"
}

func writeAuthError(w http.ResponseWriter, err error) {
	kind := apierrors.KindOf(err)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(apierrors.HTTPStatus(kind))
	_ = json.NewEncoder(w).Encode(map[string]string{
		"code": string(kind), "message": apierrors.PublicOf(err),
	})
}

// RateLimiter bounds request rate per principal, satisfying FR-059.
type RateLimiter struct {
	limit  int
	window time.Duration
	seen   map[string][]time.Time
	now    func() time.Time
}

func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	if limit <= 0 {
		limit = 100
	}
	if window <= 0 {
		window = time.Minute
	}
	return &RateLimiter{limit: limit, window: window, seen: map[string][]time.Time{}, now: time.Now}
}

// Allow reports whether a key may proceed.
func (rl *RateLimiter) Allow(key string) bool {
	now := rl.now()
	cutoff := now.Add(-rl.window)

	kept := rl.seen[key][:0]
	for _, t := range rl.seen[key] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= rl.limit {
		rl.seen[key] = kept
		return false
	}
	rl.seen[key] = append(kept, now)
	return true
}
