package postgres

import (
	"context"
	"fmt"
	"time"
)

// UserAdminRow is one line of the tenant's user listing: identity plus the
// state an administrator acts on. No secret material appears here — hashes and
// sealed secrets reduce to booleans before they leave the repository.
type UserAdminRow struct {
	PrincipalID   string
	Identity      string
	Role          string
	Active        bool
	MFAEnrolled   bool
	HasPassword   bool
	LastLoginAt   *time.Time
	InvitePending bool
	InviteExpires *time.Time
}

// ListUsers returns every principal in ONE tenant, with any open, unexpired
// invite surfaced as a pending flag. Tenant scoping happens here, in the
// query, so a handler cannot forget it.
func (r *AuthRepo) ListUsers(ctx context.Context, tenantID string) ([]UserAdminRow, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT p.id, p.identity, p.role, p.active,
		       p.mfa_enrolled_at IS NOT NULL,
		       COALESCE(p.password_hash, '') <> '',
		       p.last_login_at,
		       i.id IS NOT NULL,
		       i.expires_at
		FROM principal p
		LEFT JOIN invite i ON i.principal_id = p.id
		     AND i.redeemed_at IS NULL AND i.expires_at > now()
		WHERE p.tenant_id = $1
		ORDER BY p.identity`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()

	var out []UserAdminRow
	for rows.Next() {
		var u UserAdminRow
		if err := rows.Scan(&u.PrincipalID, &u.Identity, &u.Role, &u.Active,
			&u.MFAEnrolled, &u.HasPassword, &u.LastLoginAt,
			&u.InvitePending, &u.InviteExpires); err != nil {
			return nil, fmt.Errorf("scan user row: %w", err)
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// SetActive flips a principal's active flag. The tenant is part of the WHERE:
// a caller can only ever reach principals of their own tenant, and a miss —
// wrong tenant or no such principal — reports false rather than error, so the
// handler renders both identically (FR: no cross-tenant existence oracle).
func (r *AuthRepo) SetActive(ctx context.Context, tenantID, principalID string, active bool) (bool, error) {
	tag, err := r.pool.Exec(ctx, `
		UPDATE principal SET active = $3
		WHERE id = $2 AND tenant_id = $1`, tenantID, principalID, active)
	if err != nil {
		return false, fmt.Errorf("set active: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// SetRole changes a principal's role, tenant-scoped exactly like SetActive.
// Role validity is the service's concern; this only persists.
func (r *AuthRepo) SetRole(ctx context.Context, tenantID, principalID, role string) (bool, error) {
	tag, err := r.pool.Exec(ctx, `
		UPDATE principal SET role = $3
		WHERE id = $2 AND tenant_id = $1`, tenantID, principalID, role)
	if err != nil {
		return false, fmt.Errorf("set role: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// ClearMFA removes both the sealed secret and the enrolment stamp, so the
// next login mints a fresh secret and walks the user through enrolment again.
// Clearing only one of the two would strand the account: a stale secret with
// no enrolment re-prompts against the wrong QR; an enrolment with no secret
// can never verify.
func (r *AuthRepo) ClearMFA(ctx context.Context, tenantID, principalID string) (bool, error) {
	tag, err := r.pool.Exec(ctx, `
		UPDATE principal SET mfa_secret_enc = NULL, mfa_enrolled_at = NULL
		WHERE id = $2 AND tenant_id = $1`, tenantID, principalID)
	if err != nil {
		return false, fmt.Errorf("clear mfa: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}
