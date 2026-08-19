package service

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestTheCookieCarriesItsSecurityAttributes asserts every attribute on the
// RENDERED Set-Cookie header, because that is what the browser actually sees —
// a struct field a serializer ignored would pass any struct-level check.
func TestTheCookieCarriesItsSecurityAttributes(t *testing.T) {
	s := &AuthService{} // production mode: DevInsecureCookies false

	rec := httptest.NewRecorder()
	s.setRefreshCookie(rec, "token-value", time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC))

	header := rec.Header().Get("Set-Cookie")
	for _, want := range []string{
		"__Host-siem_refresh=", "Path=/", "HttpOnly", "Secure", "SameSite=Strict",
	} {
		if !strings.Contains(header, want) {
			t.Errorf("production cookie missing %q: %s", want, header)
		}
	}
	// The expiry is the REFRESH token's own — the v1 bug this guards against
	// dated the cookie with the access expiry and logged users out on reload.
	if !strings.Contains(header, "Expires=Wed, 26 Aug 2026") {
		t.Errorf("cookie must carry the refresh expiry, got: %s", header)
	}
}

// TestDevModeDropsThePrefixWithSecure: the browser rejects a __Host- cookie
// without Secure, so dev-over-HTTP must rename rather than silently fail to
// set any cookie at all.
func TestDevModeDropsThePrefixWithSecure(t *testing.T) {
	s := &AuthService{DevInsecureCookies: true}

	rec := httptest.NewRecorder()
	s.setRefreshCookie(rec, "token-value", time.Now().Add(time.Hour))

	header := rec.Header().Get("Set-Cookie")
	if strings.Contains(header, "__Host-") {
		t.Errorf("dev mode must not use the __Host- prefix (the browser would reject it): %s", header)
	}
	if strings.Contains(header, "Secure") {
		t.Errorf("dev mode is the one place Secure is absent, by declared flag: %s", header)
	}
	for _, want := range []string{"HttpOnly", "SameSite=Strict"} {
		if !strings.Contains(header, want) {
			t.Errorf("dev mode keeps every other guarantee, missing %q: %s", want, header)
		}
	}
}

// TestClearingKillsTheCookie: logout must leave the browser with nothing to
// present, or every refresh attempt re-presents a dead credential.
func TestClearingKillsTheCookie(t *testing.T) {
	s := &AuthService{}
	rec := httptest.NewRecorder()
	s.clearRefreshCookie(rec)

	header := rec.Header().Get("Set-Cookie")
	if !strings.Contains(header, "Max-Age=0") {
		t.Errorf("clearing must expire the cookie immediately: %s", header)
	}
}
