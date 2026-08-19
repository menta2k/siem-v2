package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/menta2k/siem-v2/backend/internal/biz/tenancy"
)

type recordingAuditor struct {
	entries []map[string]string
}

func (a *recordingAuditor) Record(tenantID, principalID, action, scope, target, outcome string, _ map[string]any) {
	a.entries = append(a.entries, map[string]string{
		"tenant": tenantID, "principal": principalID,
		"action": action, "target": target, "outcome": outcome,
	})
}

func okHandler(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }

func TestUnauthenticatedRequestIsRefusedAndAudited(t *testing.T) {
	audit := &recordingAuditor{}
	a := &Authenticator{
		Resolve: func(*http.Request) (*tenancy.Principal, error) { return nil, errors.New("no credential") },
		Audit:   audit,
	}
	rec := httptest.NewRecorder()
	a.Middleware(http.HandlerFunc(okHandler)).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/flows/search", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	if len(audit.entries) != 1 || audit.entries[0]["outcome"] != "denied" {
		t.Fatalf("the failed attempt must be audited: %v", audit.entries)
	}
}

// TestRefusedRequestIsAudited: repeated refusals are themselves a signal, so
// they must be recorded, not just rejected (FR-055).
func TestRefusedRequestIsAudited(t *testing.T) {
	audit := &recordingAuditor{}
	analyst := &tenancy.Principal{ID: "p1", TenantID: "acme", Role: tenancy.RoleAnalyst, Active: true}

	handler := RequirePermission(tenancy.PermExport, audit, okHandler)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/flows/f1/export", nil)
	req = req.WithContext(tenancy.WithPrincipal(req.Context(), analyst))

	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code == http.StatusOK {
		t.Fatal("an analyst must not be able to export")
	}
	if len(audit.entries) != 1 {
		t.Fatalf("expected one audit entry, got %d", len(audit.entries))
	}
	e := audit.entries[0]
	if e["outcome"] != "denied" || e["principal"] != "p1" || e["action"] != "export" {
		t.Errorf("audit entry should identify who was refused what: %v", e)
	}
}

// TestForbiddenLooksLikeNotFound closes an enumeration channel.
func TestForbiddenLooksLikeNotFound(t *testing.T) {
	analyst := &tenancy.Principal{ID: "p1", TenantID: "acme", Role: tenancy.RoleAnalyst, Active: true}
	handler := RequirePermission(tenancy.PermManageRetention, nil, okHandler)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/retention", nil)
	req = req.WithContext(tenancy.WithPrincipal(req.Context(), analyst))
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("a forbidden resource must be indistinguishable from a missing one, got %d", rec.Code)
	}
	var body map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if strings.Contains(strings.ToLower(body["message"]), "permission") ||
		strings.Contains(strings.ToLower(body["message"]), "retention") {
		t.Errorf("the refusal must not describe what was missing: %q", body["message"])
	}
}

func TestAllowedRequestProceedsAndIsAudited(t *testing.T) {
	audit := &recordingAuditor{}
	engineer := &tenancy.Principal{ID: "p2", TenantID: "acme", Role: tenancy.RoleEngineer, Active: true}

	handler := RequirePermission(tenancy.PermExport, audit, okHandler)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/flows/f1/export", nil)
	req = req.WithContext(tenancy.WithPrincipal(req.Context(), engineer))
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("an engineer may export, got %d", rec.Code)
	}
	if len(audit.entries) != 1 || audit.entries[0]["outcome"] != "allowed" {
		t.Fatalf("successful access must be audited too: %v", audit.entries)
	}
}

// TestCredentialIsNeverAudited: the audit trail must identify the attempt
// without recording the secret that was presented.
func TestCredentialIsNeverAudited(t *testing.T) {
	audit := &recordingAuditor{}
	a := &Authenticator{
		Resolve: func(*http.Request) (*tenancy.Principal, error) { return nil, errors.New("bad") },
		Audit:   audit,
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/flows/search", nil)
	req.Header.Set("Authorization", "Bearer super-secret-token-value-12345")
	a.Middleware(http.HandlerFunc(okHandler)).ServeHTTP(httptest.NewRecorder(), req)

	for _, e := range audit.entries {
		for _, v := range e {
			if strings.Contains(v, "token-value") || strings.Contains(v, "12345") {
				t.Fatalf("the presented credential leaked into the audit trail: %v", e)
			}
		}
	}
}

func TestRateLimiter(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	rl := NewRateLimiter(3, time.Minute)
	rl.now = func() time.Time { return now }

	for i := 0; i < 3; i++ {
		if !rl.Allow("p1") {
			t.Fatalf("request %d should be allowed", i)
		}
	}
	if rl.Allow("p1") {
		t.Fatal("the fourth request within the window must be refused")
	}
	// A different principal has its own budget.
	if !rl.Allow("p2") {
		t.Error("rate limiting must be per principal, not global")
	}
	// Past the window the budget refreshes.
	now = now.Add(2 * time.Minute)
	if !rl.Allow("p1") {
		t.Error("the window should have rolled over")
	}
}
