package service

import (
	"encoding/json"
	"net/http"

	"github.com/menta2k/siem-v2/backend/internal/biz/tenancy"
	apierrors "github.com/menta2k/siem-v2/backend/internal/errors"
)

// ListUsers renders the caller's tenant's users for the management screen.
// Mounted behind manage_users; the tenant comes from the principal, never the
// request, so the handler cannot be asked about anyone else's tenant.
func (s *AuthService) ListUsers(w http.ResponseWriter, r *http.Request) {
	caller, err := tenancy.FromContext(r.Context())
	if err != nil {
		writeAuthErr(w, apierrors.Unauthorized(err.Error()))
		return
	}
	rows, err := s.Repo.ListUsers(r.Context(), caller.TenantID)
	if err != nil {
		writeAuthErr(w, apierrors.Internal(err.Error()))
		return
	}
	users := make([]map[string]any, 0, len(rows))
	for _, u := range rows {
		users = append(users, map[string]any{
			"principal_id":   u.PrincipalID,
			"email":          u.Identity,
			"role":           u.Role,
			"active":         u.Active,
			"mfa_enrolled":   u.MFAEnrolled,
			"has_password":   u.HasPassword,
			"last_login_at":  u.LastLoginAt,
			"invite_pending": u.InvitePending,
			"invite_expires": u.InviteExpires,
		})
	}
	writeAuthJSON(w, map[string]any{"users": users})
}

// UpdateUser applies one administrative change to a principal in the caller's
// tenant: activate/deactivate, role change, or MFA reset.
//
// Two self-lockout guards are enforced here rather than in the UI: an admin
// cannot deactivate or demote THEMSELVES, because a tenant whose last admin
// did either has nobody left able to undo it.
func (s *AuthService) UpdateUser(w http.ResponseWriter, r *http.Request) {
	caller, err := tenancy.FromContext(r.Context())
	if err != nil {
		writeAuthErr(w, apierrors.Unauthorized(err.Error()))
		return
	}
	target := r.PathValue("principalID")
	if target == "" {
		writeAuthErr(w, apierrors.InvalidInput("A principal id is required.", "missing principal id"))
		return
	}
	var req struct {
		Active   *bool   `json:"active"`
		Role     *string `json:"role"`
		ResetMFA bool    `json:"reset_mfa"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		writeAuthErr(w, apierrors.InvalidInput("The update could not be read.", "malformed user update"))
		return
	}
	if req.Active == nil && req.Role == nil && !req.ResetMFA {
		writeAuthErr(w, apierrors.InvalidInput(
			"Nothing to change: provide active, role or reset_mfa.", "empty user update"))
		return
	}

	if req.Active != nil && !*req.Active && target == caller.ID {
		writeAuthErr(w, apierrors.InvalidInput(
			"You cannot deactivate your own account.", "self-deactivation"))
		return
	}
	if req.Role != nil {
		role := tenancy.Role(*req.Role)
		if role != tenancy.RoleAnalyst && role != tenancy.RoleEngineer && role != tenancy.RoleAdmin {
			writeAuthErr(w, apierrors.InvalidInput(
				"Role must be analyst, engineer or admin.", "role="+*req.Role))
			return
		}
		if target == caller.ID && role != tenancy.RoleAdmin {
			writeAuthErr(w, apierrors.InvalidInput(
				"You cannot remove your own administrative role.", "self-demotion"))
			return
		}
	}

	// Each change is applied tenant-scoped; a miss means "no such user in YOUR
	// tenant", rendered as not-found without revealing whether the id exists
	// elsewhere.
	apply := func(what string, changed bool, err error) bool {
		if err != nil {
			writeAuthErr(w, apierrors.Internal(err.Error()))
			return false
		}
		if !changed {
			writeAuthErr(w, apierrors.NotFound("No such user in your tenant: "+target))
			return false
		}
		if s.Audit != nil {
			s.Audit.Record(caller.TenantID, caller.ID, "auth.user_"+what,
				"tenant:"+caller.TenantID, target, "allowed", nil)
		}
		return true
	}

	ctx := r.Context()
	if req.Active != nil {
		what := "deactivated"
		if *req.Active {
			what = "activated"
		}
		changed, err := s.Repo.SetActive(ctx, caller.TenantID, target, *req.Active)
		if !apply(what, changed, err) {
			return
		}
	}
	if req.Role != nil {
		changed, err := s.Repo.SetRole(ctx, caller.TenantID, target, *req.Role)
		if !apply("role_changed", changed, err) {
			return
		}
	}
	if req.ResetMFA {
		changed, err := s.Repo.ClearMFA(ctx, caller.TenantID, target)
		if !apply("mfa_reset", changed, err) {
			return
		}
	}
	writeAuthJSON(w, map[string]any{"updated": true})
}
