package profile

import (
	"fmt"
	"strings"
)

// TenantConfig is a tenant's profiler policy, stored as JSONB on the tenant
// row (like ingest_filters: what gets analyzed is tenant-level governance, not
// a feed setting).
//
// Hosts is an explicit allow-list: enabled with no hosts profiles NOTHING.
// Enabling the feature must never implicitly profile the whole estate.
type TenantConfig struct {
	Enabled bool `json:"enabled"`
	// Hosts holds exact names or single leading-wildcard patterns
	// ("*.shop.example.com").
	Hosts []string `json:"hosts"`
	// ExcludePaths drops matching path prefixes ("/health", "/metrics").
	ExcludePaths []string `json:"exclude_paths"`
	// CookieNames — when cookie capture lands (plan §3.2) — controls whether
	// names are kept or only counted. Defaults to counts-only.
	CookieNames bool `json:"cookie_names"`
	// BodyParams opts into learning request-body parameters (from F5 ASM's
	// captured body). Off by default: a body is more sensitive than a query
	// string, so profiling it is a deliberate per-tenant choice. Values are
	// always secret-filtered at capture regardless.
	BodyParams bool `json:"body_params"`
	// MinObservationsToPublish keeps one-off URLs (scanner noise) out of the
	// UI until they prove recurrent; they are still counted.
	MinObservationsToPublish int `json:"min_observations_to_publish"`
}

// DefaultTenantConfig is the value a tenant has before anyone configured
// anything: off, and profiling nothing.
func DefaultTenantConfig() TenantConfig {
	return TenantConfig{Enabled: false, Hosts: []string{}, ExcludePaths: []string{}, MinObservationsToPublish: 20}
}

const (
	// MaxHosts and MaxExcludePaths bound the config itself.
	MaxHosts        = 200
	MaxExcludePaths = 100
)

// Validate rejects configurations that would silently do something other than
// what the operator typed.
func (c TenantConfig) Validate() error {
	if len(c.Hosts) > MaxHosts {
		return fmt.Errorf("at most %d hosts are supported, got %d", MaxHosts, len(c.Hosts))
	}
	if len(c.ExcludePaths) > MaxExcludePaths {
		return fmt.Errorf("at most %d exclude paths are supported, got %d", MaxExcludePaths, len(c.ExcludePaths))
	}
	for _, h := range c.Hosts {
		h = strings.TrimSpace(h)
		if h == "" {
			return fmt.Errorf("empty host pattern")
		}
		if strings.Contains(h, "/") || strings.Contains(h, " ") {
			return fmt.Errorf("host pattern %q: a host is a name, not a URL", h)
		}
		if strings.Count(h, "*") > 1 || (strings.Contains(h, "*") && !strings.HasPrefix(h, "*.")) {
			return fmt.Errorf("host pattern %q: only a single leading '*.' wildcard is supported", h)
		}
		if h == "*." {
			return fmt.Errorf("host pattern %q matches nothing", h)
		}
	}
	for _, p := range c.ExcludePaths {
		if !strings.HasPrefix(p, "/") {
			return fmt.Errorf("exclude path %q must start with '/'", p)
		}
	}
	if c.MinObservationsToPublish < 0 {
		return fmt.Errorf("min_observations_to_publish must not be negative")
	}
	return nil
}

// MatchHost reports whether a request host falls under the allow-list.
func (c TenantConfig) MatchHost(host string) bool {
	if !c.Enabled {
		return false
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}
	// A host header may legally carry a port; the policy names hosts.
	if i := strings.LastIndex(host, ":"); i > 0 && !strings.Contains(host, "]") {
		host = host[:i]
	}
	for _, pattern := range c.Hosts {
		pattern = strings.ToLower(strings.TrimSpace(pattern))
		if suffix, ok := strings.CutPrefix(pattern, "*."); ok {
			if strings.HasSuffix(host, "."+suffix) || host == suffix {
				return true
			}
			continue
		}
		if host == pattern {
			return true
		}
	}
	return false
}

// ExcludedPath reports whether a path is excluded by prefix.
func (c TenantConfig) ExcludedPath(path string) bool {
	for _, p := range c.ExcludePaths {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}
