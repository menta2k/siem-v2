package service

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/menta2k/siem-v2/backend/internal/auth"
	"github.com/menta2k/siem-v2/backend/internal/biz/tenancy"
	"github.com/menta2k/siem-v2/backend/internal/data/postgres"
	apierrors "github.com/menta2k/siem-v2/backend/internal/errors"
)

// CreateInvite mints a one-time setup link for a new or existing principal.
//
// Mounted behind manage_users. The response is the ONLY place the encoded token
// ever appears; it is not stored, not logged, and not recoverable — an admin
// who loses it re-issues, which retires the old link.
func (s *AuthService) CreateInvite(principals *postgres.PrincipalRepo) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller, err := tenancy.FromContext(r.Context())
		if err != nil {
			writeAuthErr(w, apierrors.Unauthorized(err.Error()))
			return
		}
		var req struct {
			Email string `json:"email"`
			Role  string `json:"role"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil ||
			req.Email == "" {
			writeAuthErr(w, apierrors.InvalidInput("An email is required.", "malformed invite"))
			return
		}
		role := tenancy.Role(req.Role)
		if role != tenancy.RoleAnalyst && role != tenancy.RoleEngineer && role != tenancy.RoleAdmin {
			writeAuthErr(w, apierrors.InvalidInput(
				"Role must be analyst, engineer or admin.", "role="+req.Role))
			return
		}

		email := strings.TrimSpace(strings.ToLower(req.Email))
		// The principal id derives from the caller's tenant — an admin can only
		// ever invite into their own tenant, structurally.
		principalID := caller.TenantID + "-" + strings.SplitN(email, "@", 2)[0]

		if err := principals.Upsert(r.Context(), &tenancy.Principal{
			ID: principalID, TenantID: caller.TenantID,
			Identity: email, Role: role, Active: true,
		}); err != nil {
			writeAuthErr(w, apierrors.Internal(err.Error()))
			return
		}

		tok, err := auth.NewInviteToken(caller.TenantID, principalID)
		if err != nil {
			writeAuthErr(w, apierrors.Internal(err.Error()))
			return
		}
		if err := s.Repo.CreateInvite(r.Context(), postgres.InviteRow{
			ID:       "inv-" + principalID + "-" + s.now().Format("20060102150405"),
			TenantID: caller.TenantID, PrincipalID: principalID,
			SecretHash: tok.SecretHash(), CreatedBy: caller.ID,
			ExpiresAt: s.now().Add(auth.DefaultInviteTTL),
		}); err != nil {
			writeAuthErr(w, apierrors.Internal(err.Error()))
			return
		}

		if s.Audit != nil {
			s.Audit.Record(caller.TenantID, caller.ID, "auth.invite_issued",
				"tenant:"+caller.TenantID, principalID, "allowed",
				map[string]any{"role": string(role)})
		}
		writeAuthJSON(w, map[string]any{
			"invite_token": tok.Encode(),
			"expires_at":   s.now().Add(auth.DefaultInviteTTL),
		})
	}
}

// PreviewInvite tells the holder of a link what it is for, before they commit a
// password to it. Public: the holder has no account they can sign in with yet.
// Coarse on failure — an unusable link never says which of the reasons applies.
func (s *AuthService) PreviewInvite(w http.ResponseWriter, r *http.Request) {
	rec, _, err := s.loadInvite(r)
	if err != nil {
		writeAuthErr(w, apierrors.Unauthorized("this setup link is not usable"))
		return
	}
	writeAuthJSON(w, map[string]any{"email": rec.Identity, "role": rec.Role})
}

// RedeemInvite sets the account's first password.
//
// It deliberately grants NO session: possession of a link stays strictly below
// possession of an account, and the new user proves their password (and enrols
// MFA) through the ordinary login flow.
func (s *AuthService) RedeemInvite(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		writeAuthErr(w, apierrors.InvalidInput("A token and password are required.", "malformed redeem"))
		return
	}
	if err := auth.ValidatePassword(req.Password); err != nil {
		// The one failure that IS specific: the holder is legitimate and needs
		// to know what to fix.
		writeAuthErr(w, apierrors.InvalidInput(err.Error(), "weak password"))
		return
	}

	rec, invite, err := s.loadInviteFromToken(r, req.Token)
	if err != nil {
		writeAuthErr(w, apierrors.Unauthorized("this setup link is not usable"))
		return
	}

	// Redeem FIRST, then set the password. The one-time UPDATE is the atomic
	// guard; setting the password first would let two racing redemptions both
	// appear to succeed.
	if err := s.Repo.RedeemInvite(r.Context(), invite.ID); err != nil {
		writeAuthErr(w, apierrors.Unauthorized("this setup link is not usable"))
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		writeAuthErr(w, apierrors.Internal(err.Error()))
		return
	}
	if err := s.Repo.SetPassword(r.Context(), rec.PrincipalID, hash); err != nil {
		writeAuthErr(w, apierrors.Internal(err.Error()))
		return
	}

	if s.Audit != nil {
		s.Audit.Record(rec.TenantID, rec.PrincipalID, "auth.invite_redeemed",
			"tenant:"+rec.TenantID, invite.ID, "allowed", nil)
	}
	writeAuthJSON(w, map[string]any{"redeemed": true})
}

func (s *AuthService) loadInvite(r *http.Request) (*postgres.AuthRecord, *postgres.InviteRow, error) {
	return s.loadInviteFromToken(r, r.URL.Query().Get("token"))
}

func (s *AuthService) loadInviteFromToken(r *http.Request, encoded string) (*postgres.AuthRecord, *postgres.InviteRow, error) {
	tok, err := auth.ParseInviteToken(encoded)
	if err != nil {
		return nil, nil, err
	}
	invite, err := s.Repo.OpenInvite(r.Context(), tok.PrincipalID)
	if err != nil || invite == nil {
		return nil, nil, auth.ErrInvalidInviteToken
	}
	if invite.TenantID != tok.TenantID || !tok.MatchesHash(invite.SecretHash) {
		return nil, nil, auth.ErrInvalidInviteToken
	}
	if s.now().After(invite.ExpiresAt) {
		return nil, nil, auth.ErrInvalidInviteToken
	}
	rec, err := s.Repo.ByID(r.Context(), tok.PrincipalID)
	if err != nil || !rec.Active {
		return nil, nil, auth.ErrInvalidInviteToken
	}
	return rec, invite, nil
}
