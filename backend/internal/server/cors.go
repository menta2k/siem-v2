package server

import (
	"net/http"
	"strings"
)

// CORS permits browser access from an explicit allowlist of origins.
//
// A wildcard is deliberately not offered. This API returns tenant-scoped
// security data and accepts credentials, and `Access-Control-Allow-Origin: *`
// cannot be combined with credentials anyway — so an allowlist is both the safe
// choice and the only working one.
type CORS struct {
	// AllowedOrigins must be exact origins ("https://siem.example.com"). An empty
	// list disables cross-origin access entirely, which is the correct default
	// for a deployment serving its frontend from the same origin.
	AllowedOrigins []string
}

func (c *CORS) allowed(origin string) bool {
	for _, o := range c.AllowedOrigins {
		if strings.EqualFold(o, origin) {
			return true
		}
	}
	return false
}

// Middleware applies the CORS policy.
func (c *CORS) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		if origin != "" && c.allowed(origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Max-Age", "600")
			// Responses vary by origin, so a shared cache must not serve one
			// origin's response to another.
			w.Header().Add("Vary", "Origin")
		}

		if r.Method == http.MethodOptions {
			// A preflight from a disallowed origin gets no CORS headers and a bare
			// 204: the browser refuses the real request, and we disclose nothing
			// about what would have been permitted.
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
