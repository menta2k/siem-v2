//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/menta2k/siem-v2/backend/internal/auth"
	"github.com/menta2k/siem-v2/backend/internal/biz/tenancy"
	"github.com/menta2k/siem-v2/backend/internal/data/postgres"
	"github.com/menta2k/siem-v2/backend/internal/service"
)

// TestUserAdministration covers the management surface behind manage_users:
// listing the tenant's users, deactivating, reactivating, changing role and
// resetting MFA — every operation scoped to the CALLER's tenant, with the two
// self-lockout guards (you cannot deactivate or demote yourself).
func TestUserAdministration(t *testing.T) {
	ctx := context.Background()
	pool, err := postgres.Connect(ctx, dsn(), 5, 1)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()
	if err := postgres.Migrate(ctx, pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	principals := postgres.NewPrincipalRepo(pool)
	for _, ten := range [][2]string{{"ua-acme", "UA Acme"}, {"ua-globex", "UA Globex"}} {
		if err := principals.EnsureTenant(ctx, ten[0], ten[1], 0, 0); err != nil {
			t.Fatalf("tenant: %v", err)
		}
	}
	seed := []*tenancy.Principal{
		{ID: "ua-admin", TenantID: "ua-acme", Identity: "ua-admin@acme.example.com", Role: tenancy.RoleAdmin, Active: true},
		{ID: "ua-analyst", TenantID: "ua-acme", Identity: "ua-analyst@acme.example.com", Role: tenancy.RoleAnalyst, Active: true},
		{ID: "ua-outsider", TenantID: "ua-globex", Identity: "ua-outsider@globex.example.com", Role: tenancy.RoleAdmin, Active: true},
	}
	for _, p := range seed {
		if err := principals.Upsert(ctx, p); err != nil {
			t.Fatalf("principal: %v", err)
		}
	}

	authRepo := postgres.NewAuthRepo(pool)
	svc := &service.AuthService{Repo: authRepo}
	admin := &tenancy.Principal{ID: "ua-admin", TenantID: "ua-acme",
		Identity: "ua-admin@acme.example.com", Role: tenancy.RoleAdmin, Active: true}

	// Route through a real mux with the production patterns, so the path
	// variables the handlers read are the ones the server actually binds.
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/users", svc.ListUsers)
	mux.HandleFunc("POST /api/v1/users/{principalID}", svc.UpdateUser)
	do := func(caller *tenancy.Principal, method, path, body string, _ http.HandlerFunc) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req = req.WithContext(tenancy.WithPrincipal(req.Context(), caller))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}

	t.Run("list shows only the caller's tenant", func(t *testing.T) {
		rec := do(admin, http.MethodGet, "/api/v1/users", "", svc.ListUsers)
		if rec.Code != http.StatusOK {
			t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
		}
		var res struct {
			Users []struct {
				PrincipalID string `json:"principal_id"`
				Email       string `json:"email"`
				Role        string `json:"role"`
				Active      bool   `json:"active"`
				MFAEnrolled bool   `json:"mfa_enrolled"`
				HasPassword bool   `json:"has_password"`
			} `json:"users"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
			t.Fatalf("decode: %v", err)
		}
		ids := map[string]bool{}
		for _, u := range res.Users {
			ids[u.PrincipalID] = true
		}
		if !ids["ua-admin"] || !ids["ua-analyst"] {
			t.Errorf("both acme users must be listed, got %v", ids)
		}
		if ids["ua-outsider"] {
			t.Error("a user from another tenant leaked into the list")
		}
	})

	t.Run("deactivate, then reactivate", func(t *testing.T) {
		rec := do(admin, http.MethodPost, "/api/v1/users/ua-analyst", `{"active":false}`, svc.UpdateUser)
		if rec.Code != http.StatusOK {
			t.Fatalf("deactivate: %d %s", rec.Code, rec.Body.String())
		}
		got, err := authRepo.ByID(ctx, "ua-analyst")
		if err != nil {
			t.Fatalf("read back: %v", err)
		}
		if got.Active {
			t.Error("deactivation did not persist")
		}
		rec = do(admin, http.MethodPost, "/api/v1/users/ua-analyst", `{"active":true}`, svc.UpdateUser)
		if rec.Code != http.StatusOK {
			t.Fatalf("reactivate: %d %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("role change persists", func(t *testing.T) {
		rec := do(admin, http.MethodPost, "/api/v1/users/ua-analyst", `{"role":"engineer"}`, svc.UpdateUser)
		if rec.Code != http.StatusOK {
			t.Fatalf("role change: %d %s", rec.Code, rec.Body.String())
		}
		got, _ := authRepo.ByID(ctx, "ua-analyst")
		if got.Role != "engineer" {
			t.Errorf("role = %q, want engineer", got.Role)
		}
		if rec := do(admin, http.MethodPost, "/api/v1/users/ua-analyst", `{"role":"superuser"}`, svc.UpdateUser); rec.Code != http.StatusBadRequest {
			t.Errorf("an unknown role must be refused, got %d", rec.Code)
		}
	})

	t.Run("self-lockout guards", func(t *testing.T) {
		if rec := do(admin, http.MethodPost, "/api/v1/users/ua-admin", `{"active":false}`, svc.UpdateUser); rec.Code != http.StatusBadRequest {
			t.Errorf("deactivating yourself must be refused, got %d: %s", rec.Code, rec.Body.String())
		}
		if rec := do(admin, http.MethodPost, "/api/v1/users/ua-admin", `{"role":"analyst"}`, svc.UpdateUser); rec.Code != http.StatusBadRequest {
			t.Errorf("demoting yourself must be refused, got %d: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("cross-tenant target reads as not found", func(t *testing.T) {
		rec := do(admin, http.MethodPost, "/api/v1/users/ua-outsider", `{"active":false}`, svc.UpdateUser)
		if rec.Code != http.StatusNotFound {
			t.Errorf("another tenant's user must be indistinguishable from a missing one, got %d", rec.Code)
		}
		got, _ := authRepo.ByID(ctx, "ua-outsider")
		if !got.Active {
			t.Error("the cross-tenant write must not have landed")
		}
	})

	t.Run("mfa reset clears enrolment so login re-enrols", func(t *testing.T) {
		if err := authRepo.SetMFASecret(ctx, "ua-analyst", "sealed-blob"); err != nil {
			t.Fatalf("seed secret: %v", err)
		}
		if err := authRepo.ConfirmMFAEnrolment(ctx, "ua-analyst"); err != nil {
			t.Fatalf("confirm: %v", err)
		}
		rec := do(admin, http.MethodPost, "/api/v1/users/ua-analyst", `{"reset_mfa":true}`, svc.UpdateUser)
		if rec.Code != http.StatusOK {
			t.Fatalf("reset: %d %s", rec.Code, rec.Body.String())
		}
		got, _ := authRepo.ByID(ctx, "ua-analyst")
		if got.MFAEnrolled || got.MFASecretEnc != "" {
			t.Error("reset must clear both the secret and the enrolment stamp")
		}
	})

	t.Run("open invite is visible on the listing", func(t *testing.T) {
		tok, err := auth.NewInviteToken("ua-acme", "ua-analyst")
		if err != nil {
			t.Fatalf("token: %v", err)
		}
		err = authRepo.CreateInvite(ctx, postgres.InviteRow{
			ID: "inv-ua-analyst-" + time.Now().Format("150405.000000000"), TenantID: "ua-acme", PrincipalID: "ua-analyst",
			SecretHash: tok.SecretHash(), CreatedBy: "ua-admin",
			ExpiresAt: time.Now().Add(time.Hour),
		})
		if err != nil {
			t.Fatalf("invite: %v", err)
		}
		rec := do(admin, http.MethodGet, "/api/v1/users", "", svc.ListUsers)
		var res struct {
			Users []struct {
				PrincipalID   string `json:"principal_id"`
				InvitePending bool   `json:"invite_pending"`
			} `json:"users"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
			t.Fatalf("decode: %v", err)
		}
		found := false
		for _, u := range res.Users {
			if u.PrincipalID == "ua-analyst" {
				found = u.InvitePending
			}
		}
		if !found {
			t.Error("an open, unexpired invite must show as pending on the listing")
		}
	})
}
