package conf

import (
	"fmt"
	"os"
	"strings"
)

// Resolver turns a secret *reference* from configuration into a secret value.
//
// Configuration files carry references such as "env:SIEM_PG_DSN", never values.
// This is what lets configuration be committed while satisfying FR-057's
// requirement that credentials come from the environment or a secret manager.
type Resolver interface {
	Resolve(ref string) (string, error)
}

// EnvResolver resolves "env:NAME" references from the process environment.
// A production deployment substitutes a secret-manager resolver here without
// any change to the configuration files themselves.
type EnvResolver struct{}

func (EnvResolver) Resolve(ref string) (string, error) {
	scheme, name, ok := strings.Cut(ref, ":")
	if !ok {
		return "", fmt.Errorf("secret reference %q is not in scheme:name form; "+
			"configuration must not contain literal secret values", ref)
	}
	switch scheme {
	case "env":
		v, present := os.LookupEnv(name)
		if !present {
			return "", fmt.Errorf("secret %q not set in environment", name)
		}
		if v == "" {
			return "", fmt.Errorf("secret %q is set but empty", name)
		}
		return v, nil
	default:
		return "", fmt.Errorf("unsupported secret scheme %q in reference %q", scheme, ref)
	}
}
