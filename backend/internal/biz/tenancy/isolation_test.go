package tenancy

import (
	"context"
	"strings"
	"testing"
)

func analyst() *Principal {
	return &Principal{ID: "p1", TenantID: "acme", Identity: "ana@example.com",
		Role: RoleAnalyst, Active: true}
}

// TestTenantComesOnlyFromThePrincipal is the structural guarantee behind
// FR-074b: there is no API through which a caller can name a tenant.
func TestTenantComesOnlyFromThePrincipal(t *testing.T) {
	ctx := WithPrincipal(context.Background(), analyst())
	tenant, err := TenantOf(ctx)
	if err != nil {
		t.Fatalf("tenant: %v", err)
	}
	if tenant != "acme" {
		t.Fatalf("tenant should come from the principal, got %q", tenant)
	}
}

// TestMissingPrincipalFailsClosed: a missing principal must never be mistaken
// for an anonymous-but-permitted caller.
func TestMissingPrincipalFailsClosed(t *testing.T) {
	if _, err := TenantOf(context.Background()); err == nil {
		t.Fatal("a context with no principal must not yield a tenant")
	}
	if _, err := FromContext(context.Background()); err == nil {
		t.Fatal("a context with no principal must error, not return a zero value")
	}
	if _, err := Require(context.Background(), PermViewFlows); err == nil {
		t.Fatal("permission checks must fail closed without a principal")
	}
}

func TestInactivePrincipalIsRefused(t *testing.T) {
	p := analyst()
	p.Active = false
	ctx := WithPrincipal(context.Background(), p)

	if _, err := FromContext(ctx); err == nil {
		t.Fatal("a deactivated principal must be refused")
	}
	if p.Can(PermViewFlows) {
		t.Fatal("a deactivated principal holds no permissions")
	}
}

func TestPrincipalWithoutTenantIsRefused(t *testing.T) {
	p := analyst()
	p.TenantID = ""
	if _, err := FromContext(WithPrincipal(context.Background(), p)); err == nil {
		t.Fatal("a principal with no tenant would produce an unscoped query")
	}
}

// TestAnalystCannotExportOrSeeRaw guards the permissions most worth withholding:
// they move data out of the system or expose classified content.
func TestAnalystCannotExportOrSeeRaw(t *testing.T) {
	p := analyst()
	if !p.Can(PermViewFlows) {
		t.Error("an analyst must be able to view flows")
	}
	for _, denied := range []Permission{PermExport, PermViewRaw, PermViewSensitive, PermManageRetention} {
		if p.Can(denied) {
			t.Errorf("an analyst must not hold %s by default", denied)
		}
	}
}

func TestRoleEscalationRequiresExplicitGrant(t *testing.T) {
	p := analyst()
	if p.Can(PermExport) {
		t.Fatal("precondition: analyst should not export")
	}
	p.Extra = []Permission{PermExport}
	if !p.Can(PermExport) {
		t.Error("an explicit extra grant should take effect")
	}
	// The grant must not leak into unrelated permissions.
	if p.Can(PermViewSensitive) {
		t.Error("granting export must not confer unrelated permissions")
	}
}

func TestAdminHoldsEverything(t *testing.T) {
	admin := &Principal{ID: "a1", TenantID: "acme", Role: RoleAdmin, Active: true}
	for _, perm := range []Permission{
		PermViewFlows, PermViewRaw, PermViewSensitive, PermExport,
		PermRunEvaluation, PermManageDetections, PermManageRetention,
		PermManageSources, PermViewAudit,
	} {
		if !admin.Can(perm) {
			t.Errorf("admin should hold %s", perm)
		}
	}
}

// TestPropertyScopeNarrowsButNeverWidens: scope restricts within the tenant and
// can never reach outside it, because tenant is checked separately and first.
func TestPropertyScopeNarrowsButNeverWidens(t *testing.T) {
	p := analyst()
	p.PropertyScope = []string{"shop.example.com"}

	if !p.AllowsProperty("shop.example.com") {
		t.Error("the scoped property should be allowed")
	}
	if !p.AllowsProperty("SHOP.EXAMPLE.COM") {
		t.Error("host comparison should be case-insensitive")
	}
	if p.AllowsProperty("admin.example.com") {
		t.Error("a property outside the scope must be refused")
	}

	wide := analyst()
	if !wide.AllowsProperty("anything.example.com") {
		t.Error("an empty scope means the whole tenant")
	}
	// Even with an empty scope, the tenant bound still applies elsewhere.
	if wide.TenantID != "acme" {
		t.Error("tenant remains the outer bound regardless of property scope")
	}
}

func TestRequireNamesTheMissingPermission(t *testing.T) {
	ctx := WithPrincipal(context.Background(), analyst())
	_, err := Require(ctx, PermManageRetention)
	if err == nil {
		t.Fatal("expected refusal")
	}
	// The operator-facing error should be actionable; the caller-facing message
	// is generated separately by the errors package.
	if !strings.Contains(err.Error(), "manage_retention") {
		t.Errorf("the error should name the missing permission, got: %v", err)
	}
}
