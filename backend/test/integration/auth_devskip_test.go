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

// TestDevSkipMFALogsInWithoutASecondStep covers the development convenience of
// SIEM_DEV_SKIP_MFA: with the flag on, a correct password completes the
// session in one step; with it off, the same account is still challenged.
//
// The flag must change ONLY the happy path — a wrong password is refused
// identically in both modes, so the bypass cannot weaken password checking.
func TestDevSkipMFALogsInWithoutASecondStep(t *testing.T) {
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
	if err := principals.EnsureTenant(ctx, "acme", "Acme Corp", 0, 0); err != nil {
		t.Fatalf("tenant: %v", err)
	}
	p := &tenancy.Principal{
		ID: "it-devskip-admin", TenantID: "acme",
		Identity: "devskip-admin@acme.example.com", Role: tenancy.RoleAdmin, Active: true,
	}
	if err := principals.Upsert(ctx, p); err != nil {
		t.Fatalf("principal: %v", err)
	}
	authRepo := postgres.NewAuthRepo(pool)
	hash, err := auth.HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if err := authRepo.SetPassword(ctx, p.ID, hash); err != nil {
		t.Fatalf("set password: %v", err)
	}

	newSvc := func(skip bool) *service.AuthService {
		issuer, err := auth.NewTokenIssuer(strings.Repeat("k", 32), 10*time.Minute, time.Hour, nil)
		if err != nil {
			t.Fatalf("issuer: %v", err)
		}
		sealer, err := auth.NewSealer([]byte(strings.Repeat("s", 32)))
		if err != nil {
			t.Fatalf("sealer: %v", err)
		}
		return &service.AuthService{
			Repo: authRepo, Tokens: issuer, Sealer: sealer,
			Issuer: "SIEM v2 test", DevInsecureCookies: true, DevSkipMFA: skip,
		}
	}

	login := func(svc *service.AuthService, password string) *httptest.ResponseRecorder {
		body := `{"email":"devskip-admin@acme.example.com","password":` +
			mustJSON(t, password) + `}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		svc.Login(rec, req)
		return rec
	}

	t.Run("flag on: one step to a full session", func(t *testing.T) {
		rec := login(newSvc(true), "correct horse battery staple")
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
		}
		var res struct {
			AccessToken string          `json:"access_token"`
			MFARequired bool            `json:"mfa_required"`
			User        json.RawMessage `json:"user"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if res.AccessToken == "" {
			t.Error("dev skip must complete the session: no access token returned")
		}
		if res.MFARequired {
			t.Error("dev skip must not also demand a code")
		}
		if len(res.User) == 0 {
			t.Error("the completed session must carry the profile the UI renders")
		}
		if cookie := rec.Header().Get("Set-Cookie"); !strings.Contains(cookie, "siem_refresh=") {
			t.Errorf("a completed login must set the refresh cookie, got: %q", cookie)
		}
	})

	t.Run("flag off: the same account is still challenged", func(t *testing.T) {
		rec := login(newSvc(false), "correct horse battery staple")
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 challenge, got %d: %s", rec.Code, rec.Body.String())
		}
		var res struct {
			AccessToken string `json:"access_token"`
			MFARequired bool   `json:"mfa_required"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if !res.MFARequired {
			t.Error("without the flag the second step is mandatory")
		}
		if res.AccessToken != "" {
			t.Error("no access token may exist before the code verifies")
		}
	})

	t.Run("flag on: a wrong password is still refused", func(t *testing.T) {
		rec := login(newSvc(true), "not the password")
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("the bypass must not weaken password checking: got %d: %s",
				rec.Code, rec.Body.String())
		}
	})
}

func mustJSON(t *testing.T, s string) string {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}
