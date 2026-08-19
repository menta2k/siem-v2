// Package tenancy resolves who is calling and what they may see.
//
// The governing rule, from research.md R8: VictoriaLogs' tenancy headers are
// unauthenticated and advisory, so isolation is entirely our responsibility.
// Tenant is therefore derived from the authenticated principal and never from
// anything the caller sends.
package tenancy

import (
	"context"
	"fmt"
	"strings"
)

// Permission names a capability a principal may hold.
type Permission string

const (
	PermViewFlows        Permission = "view_flows"
	PermViewRaw          Permission = "view_raw"
	PermViewSensitive    Permission = "view_sensitive"
	PermExport           Permission = "export"
	PermRunEvaluation    Permission = "run_evaluation"
	PermManageDetections Permission = "manage_detections"
	PermManageRetention  Permission = "manage_retention"
	PermManageSources    Permission = "manage_sources"
	PermViewAudit        Permission = "view_audit"
	PermManageUsers      Permission = "manage_users"
)

// Role is a named bundle of permissions.
type Role string

const (
	RoleAnalyst  Role = "analyst"
	RoleEngineer Role = "engineer"
	RoleAdmin    Role = "admin"
)

// rolePermissions defines what each role may do.
//
// Note what analyst does NOT get: viewing raw payloads, viewing masked sensitive
// fields, and exporting. Those move data out of the system or expose classified
// content, so they are granted deliberately rather than by default.
var rolePermissions = map[Role][]Permission{
	RoleAnalyst: {PermViewFlows, PermRunEvaluation},
	RoleEngineer: {
		PermViewFlows, PermViewRaw, PermRunEvaluation,
		PermExport, PermManageDetections,
	},
	RoleAdmin: {
		PermViewFlows, PermViewRaw, PermViewSensitive, PermExport,
		PermRunEvaluation, PermManageDetections, PermManageRetention,
		PermManageSources, PermViewAudit, PermManageUsers,
	},
}

// Principal is an authenticated caller.
type Principal struct {
	ID       string
	TenantID string
	Identity string
	Role     Role
	// PropertyScope restricts the principal to specific hosts within the tenant.
	// Empty means the whole tenant; it never widens beyond it.
	PropertyScope []string
	// Extra permissions granted beyond the role.
	Extra  []Permission
	Active bool
}

// Can reports whether the principal holds a permission.
func (p *Principal) Can(perm Permission) bool {
	if p == nil || !p.Active {
		return false
	}
	for _, granted := range rolePermissions[p.Role] {
		if granted == perm {
			return true
		}
	}
	for _, granted := range p.Extra {
		if granted == perm {
			return true
		}
	}
	return false
}

// AllowsProperty reports whether a host is within the principal's scope.
func (p *Principal) AllowsProperty(host string) bool {
	if p == nil || !p.Active {
		return false
	}
	if len(p.PropertyScope) == 0 {
		return true // whole tenant, still bounded by TenantID
	}
	for _, allowed := range p.PropertyScope {
		if strings.EqualFold(allowed, host) {
			return true
		}
	}
	return false
}

type contextKey struct{}

// WithPrincipal attaches an authenticated principal to a context.
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, contextKey{}, p)
}

// FromContext retrieves the principal.
//
// It returns an error rather than a zero value when absent. A missing principal
// must be impossible to mistake for an anonymous-but-permitted one, which is
// exactly the bug a zero value invites.
func FromContext(ctx context.Context) (*Principal, error) {
	p, ok := ctx.Value(contextKey{}).(*Principal)
	if !ok || p == nil {
		return nil, fmt.Errorf("no authenticated principal on the context")
	}
	if !p.Active {
		return nil, fmt.Errorf("principal %s is not active", p.ID)
	}
	if p.TenantID == "" {
		return nil, fmt.Errorf("principal %s has no tenant", p.ID)
	}
	return p, nil
}

// TenantOf returns the caller's tenant.
//
// This is the ONLY way a tenant reaches a query. There is deliberately no
// variant that accepts a tenant argument, because such a function would make
// cross-tenant access expressible — which FR-074b forbids at the level of the
// API's shape, not merely its behaviour.
func TenantOf(ctx context.Context) (string, error) {
	p, err := FromContext(ctx)
	if err != nil {
		return "", err
	}
	return p.TenantID, nil
}

// Require returns an error unless the principal holds the permission.
func Require(ctx context.Context, perm Permission) (*Principal, error) {
	p, err := FromContext(ctx)
	if err != nil {
		return nil, err
	}
	if !p.Can(perm) {
		return nil, fmt.Errorf("principal %s (role %s) lacks %s", p.ID, p.Role, perm)
	}
	return p, nil
}
