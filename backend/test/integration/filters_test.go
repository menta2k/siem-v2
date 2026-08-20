//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/menta2k/siem-v2/backend/internal/biz/tenancy"
	"github.com/menta2k/siem-v2/backend/internal/data/postgres"
	"github.com/menta2k/siem-v2/backend/internal/ingest/filter"
	"github.com/menta2k/siem-v2/backend/internal/service"
)

func TestIngestFilterLifecycle(t *testing.T) {
	ctx := context.Background()
	pool, err := postgres.Connect(ctx, dsn(), 2, 1)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()
	if err := postgres.Migrate(ctx, pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	principals := postgres.NewPrincipalRepo(pool)
	for _, ten := range []string{"fl-acme", "fl-globex"} {
		if err := principals.EnsureTenant(ctx, ten, ten, 0, 0); err != nil {
			t.Fatalf("tenant: %v", err)
		}
	}
	svc := &service.FilterService{Repo: postgres.NewFilterRepo(pool)}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/filters", svc.Get)
	mux.HandleFunc("POST /api/v1/filters", svc.Set)
	do := func(tenant, method, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "/api/v1/filters", strings.NewReader(body))
		req = req.WithContext(tenancy.WithPrincipal(req.Context(), &tenancy.Principal{
			ID: tenant + "-adm", TenantID: tenant, Role: tenancy.RoleAdmin, Active: true,
		}))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}

	// Replace, read back, tenant isolation, footgun rejection.
	rules := `{"rules":[{"field":"request_path","op":"prefix","values":["/nginx_status"]}]}`
	if rec := do("fl-acme", http.MethodPost, rules); rec.Code != http.StatusOK {
		t.Fatalf("set: %d %s", rec.Code, rec.Body.String())
	}
	rec := do("fl-acme", http.MethodGet, "")
	var got struct {
		Rules []filter.Rule `json:"rules"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || len(got.Rules) != 1 {
		t.Fatalf("read back: %v %s", err, rec.Body.String())
	}
	rec = do("fl-globex", http.MethodGet, "")
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if len(got.Rules) != 0 {
		t.Fatal("another tenant's rules leaked")
	}
	if rec := do("fl-acme", http.MethodPost, `{"rules":[{"field":"request_path","op":"prefix","values":[""]}]}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("the drop-everything footgun must be rejected, got %d", rec.Code)
	}
	// The repo's All (the ingest cache's source) sees the stored set.
	all, err := postgres.NewFilterRepo(pool).All(ctx)
	if err != nil {
		t.Fatalf("all: %v", err)
	}
	if len(all["fl-acme"]) != 1 {
		t.Fatalf("ingest cache source must see the rules: %v", all)
	}
	// Clearing replaces with empty.
	if rec := do("fl-acme", http.MethodPost, `{"rules":[]}`); rec.Code != http.StatusOK {
		t.Fatalf("clear: %d", rec.Code)
	}
}
