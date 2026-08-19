// Package service holds HTTP service implementations shared by the binaries.
package service

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/menta2k/siem-v2/backend/internal/auth"
	"github.com/menta2k/siem-v2/backend/internal/biz/tenancy"
	"github.com/menta2k/siem-v2/backend/internal/data/postgres"
	apierrors "github.com/menta2k/siem-v2/backend/internal/errors"
)

// refreshCookieName is the cookie carrying the refresh token.
//
// The __Host- prefix is enforced by the browser: it refuses the cookie unless
// it is Secure, has no Domain, and has Path=/. That makes the guarantees below
// impossible to weaken later by editing one attribute — a subdomain cannot set
// or overwrite it, which matters because a refresh token mints access tokens.
const refreshCookieName = "__Host-siem_refresh"

// Auditor records auth events.
type Auditor interface {
	Record(tenantID, principalID, action, scope, target, outcome string, detail map[string]any)
}

// Limiter bounds attempt rates per key.
type Limiter interface {
	Allow(key string) bool
}

// AuthService implements login, MFA, refresh, logout and invites.
type AuthService struct {
	Repo    *postgres.AuthRepo
	Tokens  *auth.TokenIssuer
	Sealer  *auth.Sealer
	Audit   Auditor
	Limiter Limiter
	Issuer  string // shown in authenticator apps
	Now     func() time.Time
	// DevInsecureCookies drops the Secure attribute for plain-HTTP local work.
	// The __Host- prefix is dropped with it, because the browser rejects the
	// prefix without Secure. Never set in production.
	DevInsecureCookies bool
	// DevSkipMFA completes login on the password alone, skipping the TOTP step
	// entirely so local development does not need an authenticator app. Only
	// the happy path changes: password verification, rate limiting and audit
	// are untouched. Never set in production.
	DevSkipMFA bool
}

func (s *AuthService) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now().UTC()
}

// profile is what the frontend needs to render the session: identity plus the
// permission map that drives `can`.
type profile struct {
	PrincipalID string   `json:"principal_id"`
	Email       string   `json:"email"`
	TenantID    string   `json:"tenant_id"`
	Role        string   `json:"role"`
	Permissions []string `json:"permissions"`
}

func profileOf(rec *postgres.AuthRecord) profile {
	p := &tenancy.Principal{
		ID: rec.PrincipalID, TenantID: rec.TenantID,
		Identity: rec.Identity, Role: tenancy.Role(rec.Role), Active: rec.Active,
	}
	perms := []string{}
	for _, perm := range []tenancy.Permission{
		tenancy.PermViewFlows, tenancy.PermViewRaw, tenancy.PermViewSensitive,
		tenancy.PermExport, tenancy.PermRunEvaluation, tenancy.PermManageDetections,
		tenancy.PermManageRetention, tenancy.PermManageSources, tenancy.PermViewAudit,
		tenancy.PermManageUsers,
	} {
		if p.Can(perm) {
			perms = append(perms, string(perm))
		}
	}
	return profile{
		PrincipalID: rec.PrincipalID, Email: rec.Identity,
		TenantID: rec.TenantID, Role: rec.Role, Permissions: perms,
	}
}

// Login is step one: password verification.
//
// Every failure path returns the same error and burns comparable work, so the
// endpoint cannot be used to enumerate valid addresses — an unknown email, a
// deactivated account and a not-yet-redeemed invite all look exactly like a
// wrong password from outside.
func (s *AuthService) Login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil ||
		req.Email == "" || req.Password == "" {
		writeAuthErr(w, apierrors.InvalidInput("Email and password are required.", "malformed login"))
		return
	}
	if s.Limiter != nil && !s.Limiter.Allow("login:"+strings.ToLower(req.Email)) {
		writeAuthErr(w, apierrors.New(apierrors.KindUnavailable,
			"Too many attempts. Please wait before trying again.", "login rate limited"))
		return
	}

	rec, err := s.Repo.ByEmail(r.Context(), strings.TrimSpace(strings.ToLower(req.Email)))
	if err != nil || rec.PasswordHash == "" || !rec.Active {
		// Unknown address, unredeemed invite, or deactivated account: burn the
		// same work a real verification costs, then refuse coarsely.
		auth.VerifyDummyPassword()
		s.auditFailed(req.Email, "unknown-or-unusable")
		writeAuthErr(w, apierrors.Unauthorized("credentials did not verify"))
		return
	}
	if err := auth.VerifyPassword(req.Password, rec.PasswordHash); err != nil {
		s.audit(rec, "auth.failed", "denied", map[string]any{"step": "password"})
		writeAuthErr(w, apierrors.Unauthorized("credentials did not verify"))
		return
	}

	identity := auth.Identity{
		PrincipalID: rec.PrincipalID, Email: rec.Identity,
		TenantID: rec.TenantID, Role: rec.Role,
	}

	// Development bypass: the password alone completes the session. Guarded by
	// an env-derived flag that logs loudly at startup, exactly like the
	// insecure-cookie switch.
	if s.DevSkipMFA {
		s.audit(rec, "auth.login_dev_skip_mfa", "allowed", nil)
		s.completeLogin(w, r, rec)
		return
	}

	// MFA is always the second step. An account without an enrolment gets one
	// minted NOW and confirmed by the first successful code — the secret is
	// stored sealed but not marked enrolled until a code proves the
	// authenticator actually has it, so a mistyped QR cannot lock the user out.
	if !rec.MFAEnrolled {
		secret, err := auth.GenerateMFASecret(s.issuer(), rec.Identity)
		if err != nil {
			writeAuthErr(w, apierrors.Internal(err.Error()))
			return
		}
		sealed, err := s.Sealer.Seal(secret.Secret)
		if err != nil {
			writeAuthErr(w, apierrors.Internal(err.Error()))
			return
		}
		if err := s.Repo.SetMFASecret(r.Context(), rec.PrincipalID, sealed); err != nil {
			writeAuthErr(w, apierrors.Internal(err.Error()))
			return
		}
		challenge, err := s.Tokens.IssueMFAChallenge(identity)
		if err != nil {
			writeAuthErr(w, apierrors.Internal(err.Error()))
			return
		}
		writeAuthJSON(w, map[string]any{
			"mfa_required": true, "enroll": true,
			"challenge_token": challenge, "provisioning_uri": secret.URI,
		})
		return
	}

	challenge, err := s.Tokens.IssueMFAChallenge(identity)
	if err != nil {
		writeAuthErr(w, apierrors.Internal(err.Error()))
		return
	}
	writeAuthJSON(w, map[string]any{"mfa_required": true, "challenge_token": challenge})
}

// VerifyMFA is step two: a TOTP code presented with the challenge token.
func (s *AuthService) VerifyMFA(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ChallengeToken string `json:"challenge_token"`
		Code           string `json:"code"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil ||
		req.ChallengeToken == "" || req.Code == "" {
		writeAuthErr(w, apierrors.InvalidInput("A challenge token and code are required.", "malformed mfa"))
		return
	}

	claims, err := s.Tokens.ParseMFAChallenge(req.ChallengeToken)
	if err != nil {
		writeAuthErr(w, apierrors.Unauthorized("challenge did not verify"))
		return
	}
	if s.Limiter != nil && !s.Limiter.Allow("mfa:"+claims.Subject) {
		writeAuthErr(w, apierrors.New(apierrors.KindUnavailable,
			"Too many attempts. Please wait before trying again.", "mfa rate limited"))
		return
	}

	rec, err := s.Repo.ByID(r.Context(), claims.Subject)
	if err != nil || !rec.Active || rec.MFASecretEnc == "" {
		writeAuthErr(w, apierrors.Unauthorized("challenge did not verify"))
		return
	}
	secret, err := s.Sealer.Open(rec.MFASecretEnc)
	if err != nil {
		writeAuthErr(w, apierrors.Internal(err.Error()))
		return
	}
	if err := auth.VerifyMFACode(secret, req.Code, s.now()); err != nil {
		s.audit(rec, "auth.failed", "denied", map[string]any{"step": "mfa"})
		writeAuthErr(w, apierrors.Unauthorized("challenge did not verify"))
		return
	}

	// A verified code is what confirms enrolment: only now is it certain the
	// authenticator actually holds the secret.
	if !rec.MFAEnrolled {
		if err := s.Repo.ConfirmMFAEnrolment(r.Context(), rec.PrincipalID); err != nil {
			writeAuthErr(w, apierrors.Internal(err.Error()))
			return
		}
		s.audit(rec, "auth.mfa_enrolled", "allowed", nil)
	}

	s.completeLogin(w, r, rec)
}

// completeLogin issues the pair, sets the cookie, and records the login.
func (s *AuthService) completeLogin(w http.ResponseWriter, r *http.Request, rec *postgres.AuthRecord) {
	pair, err := s.Tokens.IssuePair(auth.Identity{
		PrincipalID: rec.PrincipalID, Email: rec.Identity,
		TenantID: rec.TenantID, Role: rec.Role,
	})
	if err != nil {
		writeAuthErr(w, apierrors.Internal(err.Error()))
		return
	}
	_ = s.Repo.RecordLogin(r.Context(), rec.PrincipalID, s.now())
	s.audit(rec, "auth.login", "allowed", nil)

	s.setRefreshCookie(w, pair.RefreshToken, pair.RefreshExpiresAt)
	writeAuthJSON(w, map[string]any{
		"access_token": pair.AccessToken,
		"expires_at":   pair.ExpiresAt,
		"user":         profileOf(rec),
	})
}

// Refresh rotates the session.
//
// Rotation is the point: each use revokes the presented token and issues a new
// pair, so a stolen refresh token dies the first time the legitimate client
// refreshes after the theft.
func (s *AuthService) Refresh(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(s.cookieName())
	if err != nil || cookie.Value == "" {
		writeAuthErr(w, apierrors.Unauthorized("no session"))
		return
	}
	claims, err := s.Tokens.ParseRefresh(r.Context(), cookie.Value)
	if err != nil {
		writeAuthErr(w, apierrors.Unauthorized("session did not verify"))
		return
	}

	// Re-read the principal: a deactivated account's outstanding tokens stay
	// cryptographically valid, and this read is what makes deactivation take
	// effect at the next refresh rather than never.
	rec, err := s.Repo.ByID(r.Context(), claims.Subject)
	if err != nil || !rec.Active {
		writeAuthErr(w, apierrors.Unauthorized("session did not verify"))
		return
	}

	if err := s.Tokens.Revoke(r.Context(), cookie.Value); err != nil {
		writeAuthErr(w, apierrors.Internal(err.Error()))
		return
	}
	s.completeLogin(w, r, rec)
}

// Logout revokes the refresh token and clears the cookie.
//
// A logout that revokes server-side but leaves the cookie in place would have
// the browser keep presenting a dead credential on every refresh attempt.
func (s *AuthService) Logout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(s.cookieName()); err == nil && cookie.Value != "" {
		if claims, err := s.Tokens.ParseRefresh(r.Context(), cookie.Value); err == nil {
			if rec, err := s.Repo.ByID(r.Context(), claims.Subject); err == nil {
				s.audit(rec, "auth.logout", "allowed", nil)
			}
		}
		_ = s.Tokens.Revoke(r.Context(), cookie.Value)
	}
	s.clearRefreshCookie(w)
	writeAuthJSON(w, map[string]any{"signed_out": true})
}

// Me returns the authenticated caller's profile. Mounted behind the access-token
// middleware.
func (s *AuthService) Me(w http.ResponseWriter, r *http.Request) {
	p, err := tenancy.FromContext(r.Context())
	if err != nil {
		writeAuthErr(w, apierrors.Unauthorized(err.Error()))
		return
	}
	rec, err := s.Repo.ByID(r.Context(), p.ID)
	if err != nil {
		writeAuthErr(w, apierrors.Internal(err.Error()))
		return
	}
	writeAuthJSON(w, map[string]any{"user": profileOf(rec)})
}

func (s *AuthService) issuer() string {
	if s.Issuer != "" {
		return s.Issuer
	}
	return "SIEM v2"
}

func (s *AuthService) cookieName() string {
	if s.DevInsecureCookies {
		// The browser rejects a __Host- cookie without Secure, so dev-over-HTTP
		// must use an unprefixed name. Production keeps the prefix and the
		// guarantees it enforces.
		return "siem_refresh"
	}
	return refreshCookieName
}

func (s *AuthService) setRefreshCookie(w http.ResponseWriter, token string, expiresAt time.Time) {
	// gosec cannot see through refreshCookie to the composite literal and
	// reports the attributes as missing. They are set there — HttpOnly,
	// SameSite=Strict, and Secure outside dev mode — and
	// TestTheCookieCarriesItsSecurityAttributes asserts every one of them on
	// the rendered header, so the property this rule protects is checked, just
	// not here.
	//nolint:gosec // attributes set in refreshCookie and asserted on the header
	http.SetCookie(w, s.refreshCookie(token, expiresAt)) //#nosec G124 -- asserted on the rendered header
}

func (s *AuthService) clearRefreshCookie(w http.ResponseWriter) {
	c := s.refreshCookie("", time.Time{}) //#nosec G124 -- attributes set in refreshCookie, asserted on the rendered header
	c.MaxAge = -1
	//nolint:gosec // attributes set in refreshCookie and asserted on the header
	http.SetCookie(w, c) //#nosec G124 -- asserted on the rendered header
}

// refreshCookie builds the session cookie.
//
// httpOnly: the access token deliberately lives in memory and dies with the
// page, but the refresh token has to outlive it, and the only place it can do
// that safely is a cookie JavaScript cannot read — localStorage would put the
// LONGER-lived credential somewhere any XSS can reach.
//
// SameSite=Strict is the CSRF defence for the refresh endpoint: the browser
// will not attach the cookie to a cross-site request, so another origin cannot
// mint tokens with it.
//
// The expiry is the REFRESH token's own (see TokenPair.RefreshExpiresAt for the
// bug this prevents).
func (s *AuthService) refreshCookie(token string, expiresAt time.Time) *http.Cookie {
	//#nosec G124 -- Secure is conditional on the declared dev flag only; HttpOnly and
	// SameSite=Strict are unconditional, and TestTheCookieCarriesItsSecurityAttributes
	// asserts all three on the rendered production header.
	return &http.Cookie{
		Name:     s.cookieName(),
		Value:    token,
		Path:     "/",
		Expires:  expiresAt,
		HttpOnly: true,
		Secure:   !s.DevInsecureCookies,
		SameSite: http.SameSiteStrictMode,
	}
}

func (s *AuthService) audit(rec *postgres.AuthRecord, action, outcome string, detail map[string]any) {
	if s.Audit == nil {
		return
	}
	s.Audit.Record(rec.TenantID, rec.PrincipalID, action, "tenant:"+rec.TenantID, "", outcome, detail)
}

func (s *AuthService) auditFailed(presentedEmail, reason string) {
	if s.Audit == nil {
		return
	}
	// Enough to correlate repeated failures, never the credential and never
	// confirmation that the address exists.
	hint := presentedEmail
	if len(hint) > 8 {
		hint = hint[:8] + "..."
	}
	s.Audit.Record("", "presented:"+hint, "auth.failed", "", "", "denied",
		map[string]any{"reason": reason})
}

func writeAuthJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func writeAuthErr(w http.ResponseWriter, err error) {
	kind := apierrors.KindOf(err)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(apierrors.HTTPStatus(kind))
	_ = json.NewEncoder(w).Encode(map[string]string{
		"code": string(kind), "message": apierrors.PublicOf(err),
	})
}

// ResolveAccess turns a bearer access token into a Principal for the
// authentication middleware. This replaces the dev identity-string resolver.
func (s *AuthService) ResolveAccess(ctx context.Context, bearer string) (*tenancy.Principal, error) {
	claims, err := s.Tokens.ParseAccess(bearer)
	if err != nil {
		return nil, err
	}
	// Re-read the principal on every request rather than trusting the token's
	// claims: a deactivated principal's tokens stay cryptographically valid, and
	// this read is what makes deactivation take effect immediately rather than
	// up to an access-token lifetime later.
	rec, err := s.Repo.ByID(ctx, claims.Subject)
	if err != nil {
		return nil, err
	}
	if !rec.Active {
		return nil, errors.New("principal deactivated")
	}
	return &tenancy.Principal{
		ID: rec.PrincipalID, TenantID: rec.TenantID,
		Identity: rec.Identity, Role: tenancy.Role(rec.Role), Active: true,
	}, nil
}
