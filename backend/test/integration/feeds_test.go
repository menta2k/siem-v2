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

// TestFeedManagement covers the feed lifecycle: create (token shown once),
// list (no secret material), enable/disable, and token rotation with v1's
// immediate-kill semantics — the old hash is gone the moment rotate commits.
func TestFeedManagement(t *testing.T) {
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
	for _, ten := range [][2]string{{"fm-acme", "FM Acme"}, {"fm-globex", "FM Globex"}} {
		if err := principals.EnsureTenant(ctx, ten[0], ten[1], 0, 0); err != nil {
			t.Fatalf("tenant: %v", err)
		}
	}
	// A fresh name per run: the name is unique per tenant by design.
	name := "edge-" + time.Now().Format("150405.000000000")

	repo := postgres.NewFeedRepo(pool)
	svc := &service.FeedService{Repo: repo}
	admin := &tenancy.Principal{ID: "fm-admin", TenantID: "fm-acme", Role: tenancy.RoleAdmin, Active: true}
	outsider := &tenancy.Principal{ID: "fm-out", TenantID: "fm-globex", Role: tenancy.RoleAdmin, Active: true}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/feeds", svc.List)
	mux.HandleFunc("POST /api/v1/feeds", svc.Create)
	mux.HandleFunc("POST /api/v1/feeds/{feedID}", svc.Update)
	mux.HandleFunc("POST /api/v1/feeds/{feedID}/rotate", svc.Rotate)
	do := func(caller *tenancy.Principal, method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req = req.WithContext(tenancy.WithPrincipal(req.Context(), caller))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}

	var feedID, firstToken string

	t.Run("create returns the token exactly once", func(t *testing.T) {
		rec := do(admin, http.MethodPost, "/api/v1/feeds", `{"provider":"nginx","name":"`+name+`"}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
		}
		var res struct {
			Feed  map[string]any `json:"feed"`
			Token string         `json:"token"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if res.Token == "" {
			t.Fatal("the create response is the only place the token may appear")
		}
		feedID, firstToken = res.Feed["id"].(string), res.Token
		if id, _, err := auth.SplitFeedToken(firstToken); err != nil || id != feedID {
			t.Fatalf("the token's id half must be the feed id: %v", err)
		}
		if rec := do(admin, http.MethodPost, "/api/v1/feeds", `{"provider":"nginx","name":"`+name+`"}`); rec.Code != http.StatusConflict {
			t.Errorf("a duplicate name in the tenant must 409, got %d", rec.Code)
		}
		if rec := do(admin, http.MethodPost, "/api/v1/feeds", `{"provider":"exotic","name":"x-`+name+`"}`); rec.Code != http.StatusBadRequest {
			t.Errorf("an unknown provider must 400, got %d", rec.Code)
		}
	})

	t.Run("list never carries secret material", func(t *testing.T) {
		rec := do(admin, http.MethodGet, "/api/v1/feeds", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("list: %d", rec.Code)
		}
		body := rec.Body.String()
		if strings.Contains(body, "token_hash") || strings.Contains(body, "hash") {
			t.Error("the listing must not expose even the hash")
		}
		if !strings.Contains(body, feedID) {
			t.Error("the created feed must be listed")
		}
	})

	t.Run("outsider cannot see or touch the feed", func(t *testing.T) {
		if body := do(outsider, http.MethodGet, "/api/v1/feeds", "").Body.String(); strings.Contains(body, feedID) {
			t.Error("a feed leaked across tenants")
		}
		if rec := do(outsider, http.MethodPost, "/api/v1/feeds/"+feedID+"/rotate", ""); rec.Code != http.StatusNotFound {
			t.Errorf("cross-tenant rotate must read as not-found, got %d", rec.Code)
		}
	})

	t.Run("rotate kills the old token immediately", func(t *testing.T) {
		rec := do(admin, http.MethodPost, "/api/v1/feeds/"+feedID+"/rotate", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("rotate: %d %s", rec.Code, rec.Body.String())
		}
		var res struct {
			Token string `json:"token"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil || res.Token == "" {
			t.Fatalf("rotate must return the replacement token once: %v", err)
		}
		if res.Token == firstToken {
			t.Fatal("rotation must mint a fresh secret")
		}
		feeds, err := repo.ListEnabled(ctx)
		if err != nil {
			t.Fatalf("list enabled: %v", err)
		}
		_, oldSecret, _ := auth.SplitFeedToken(firstToken)
		_, newSecret, _ := auth.SplitFeedToken(res.Token)
		for _, f := range feeds {
			if f.ID != feedID {
				continue
			}
			if auth.FeedSecretMatches(oldSecret, f.TokenHash) {
				t.Error("the old token must be dead the moment rotate commits")
			}
			if !auth.FeedSecretMatches(newSecret, f.TokenHash) {
				t.Error("the new token must verify against the stored hash")
			}
		}
	})

	t.Run("disable removes the feed from the ingest working set", func(t *testing.T) {
		if rec := do(admin, http.MethodPost, "/api/v1/feeds/"+feedID, `{"enabled":false}`); rec.Code != http.StatusOK {
			t.Fatalf("disable: %d %s", rec.Code, rec.Body.String())
		}
		feeds, _ := repo.ListEnabled(ctx)
		for _, f := range feeds {
			if f.ID == feedID {
				t.Error("a disabled feed must not appear in ListEnabled — that is what the ingest cache serves from")
			}
		}
	})
}
