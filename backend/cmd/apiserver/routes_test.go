package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestEveryProtectedRouteRequiresAPermission is v2's equivalent of Casbin's
// deny-by-default: an endpoint registered on the authenticated mux without a
// RequirePermission wrapper fails the build, so the fail direction for a
// forgotten wrapper is "unreachable", never "reachable by anyone signed in".
func TestEveryProtectedRouteRequiresAPermission(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}

	// Each api.HandleFunc registration spans the pattern line and the handler
	// line; join them so the assertion sees both.
	re := regexp.MustCompile(`api\.HandleFunc\((?s).*?\)\)`)
	registrations := re.FindAllString(string(src), -1)
	if len(registrations) < 10 {
		t.Fatalf("expected to find the protected route table, got %d registrations", len(registrations))
	}

	for _, reg := range registrations {
		if !strings.Contains(reg, "server.RequirePermission(") {
			t.Errorf("protected route registered without RequirePermission:\n%s", reg)
		}
	}
}

// TestPublicOperationsAreAnExplicitSet: the public mux must list operations
// individually — a prefix would silently expose every future route sharing it.
func TestPublicOperationsAreAnExplicitSet(t *testing.T) {
	src, _ := os.ReadFile("main.go")
	if strings.Contains(string(src), `public.Handle("/api/v1/auth/"`) {
		t.Fatal("public auth routes must be listed individually, never as a prefix")
	}
	for _, want := range []string{
		"POST /api/v1/auth/login", "POST /api/v1/auth/mfa",
		"POST /api/v1/auth/refresh", "GET /api/v1/invites/preview",
	} {
		if !strings.Contains(string(src), want) {
			t.Errorf("expected explicit public registration for %q", want)
		}
	}
}
