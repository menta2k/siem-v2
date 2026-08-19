package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/menta2k/siem-v2/backend/internal/biz/tenancy"
)

// PrincipalRepo loads authenticated identities.
type PrincipalRepo struct{ pool *pgxpool.Pool }

func NewPrincipalRepo(pool *pgxpool.Pool) *PrincipalRepo { return &PrincipalRepo{pool: pool} }

// ErrNoPrincipal is returned when an identity does not resolve.
var ErrNoPrincipal = errors.New("principal not found")

// ByIdentity resolves an authenticated identity to a principal.
//
// Only active principals are returned. A deactivated account resolving
// successfully and then failing later checks would leave a window in which its
// tenant had already been used to scope a query.
func (r *PrincipalRepo) ByIdentity(ctx context.Context, identity string) (*tenancy.Principal, error) {
	var p tenancy.Principal
	var role string
	var perms []string

	err := r.pool.QueryRow(ctx, `
		SELECT id, tenant_id, identity, role, property_scope, permissions, active
		FROM principal WHERE identity = $1 AND active = TRUE`, identity).
		Scan(&p.ID, &p.TenantID, &p.Identity, &role, &p.PropertyScope, &perms, &p.Active)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNoPrincipal
		}
		return nil, fmt.Errorf("load principal: %w", err)
	}

	p.Role = tenancy.Role(role)
	for _, perm := range perms {
		p.Extra = append(p.Extra, tenancy.Permission(perm))
	}
	return &p, nil
}

// Upsert creates or updates a principal, used by seeding and administration.
func (r *PrincipalRepo) Upsert(ctx context.Context, p *tenancy.Principal) error {
	// A nil Go slice marshals to SQL NULL, which the NOT NULL columns reject.
	// Empty-but-non-nil is the correct representation of "no extra permissions"
	// and "unrestricted within the tenant", and keeping the constraint means a
	// missing scope can never be mistaken for an unset one.
	perms := make([]string, 0, len(p.Extra))
	for _, perm := range p.Extra {
		perms = append(perms, string(perm))
	}
	scope := p.PropertyScope
	if scope == nil {
		scope = []string{}
	}
	_, err := r.pool.Exec(ctx, `
		INSERT INTO principal (id, tenant_id, identity, role, property_scope, permissions, active)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT (id) DO UPDATE SET
			tenant_id = EXCLUDED.tenant_id, identity = EXCLUDED.identity,
			role = EXCLUDED.role, property_scope = EXCLUDED.property_scope,
			permissions = EXCLUDED.permissions, active = EXCLUDED.active`,
		p.ID, p.TenantID, p.Identity, string(p.Role), scope, perms, p.Active)
	if err != nil {
		return fmt.Errorf("upsert principal: %w", err)
	}
	return nil
}

// EnsureTenant creates a tenant if absent.
func (r *PrincipalRepo) EnsureTenant(ctx context.Context, id, name string, account, project uint32) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO tenant (id, name, vl_account_id, vl_project_id) VALUES ($1,$2,$3,$4)
		ON CONFLICT (id) DO NOTHING`, id, name, account, project)
	return err
}
