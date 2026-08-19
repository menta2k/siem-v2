// Package fixtures holds sanitized provider samples used by parser and scenario
// tests. This guard exists because the constitution forbids committing real
// credentials or personal data, and fixtures are the most likely place for them
// to arrive by accident: they are copied from production consoles.
package fixtures

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Patterns that indicate a fixture was not sanitized. Each is deliberately
// narrow: a guard that cries wolf gets disabled, which is worse than no guard.
var forbidden = []struct {
	name    string
	pattern *regexp.Regexp
}{
	{"AWS access key id", regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)},
	{"Cloudflare API token", regexp.MustCompile(`\b[A-Za-z0-9_-]{40}\b.*(?i:cf_api|cloudflare.{0,10}token)`)},
	{"private key block", regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----`)},
	{"JWT", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`)},
	{"authorization bearer value", regexp.MustCompile(`(?i)authorization"?\s*[:=]\s*"?bearer\s+[A-Za-z0-9._-]{20,}`)},
	{"email address", regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`)},
	{"credit card number", regexp.MustCompile(`\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b`)},
}

// luhnValidated names the checks whose regex alone produces too many false
// positives to be trusted. F5 ASM support_id values, for instance, are 16-digit
// numbers that match the Visa pattern exactly. Requiring a valid Luhn checksum
// makes the difference: real card numbers pass it, arbitrary 16-digit
// identifiers almost never do.
var luhnValidated = map[string]bool{"credit card number": true}

// luhn reports whether a digit string satisfies the Luhn checksum.
func luhn(s string) bool {
	sum, alt := 0, false
	for i := len(s) - 1; i >= 0; i-- {
		c := s[i]
		if c < '0' || c > '9' {
			return false
		}
		d := int(c - '0')
		if alt {
			if d *= 2; d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0
}

// allowedEmailDomains are safe by convention (RFC 2606 / RFC 6761) and are the
// correct thing to put in a sanitized fixture.
var allowedEmailDomains = []string{"@example.com", "@example.org", "@example.net", "@test.invalid"}

func TestFixturesAreSanitized(t *testing.T) {
	root := "."
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		content := string(data)
		for _, f := range forbidden {
			for _, m := range f.pattern.FindAllString(content, -1) {
				if f.name == "email address" && hasAllowedDomain(m) {
					continue
				}
				if luhnValidated[f.name] && !luhn(m) {
					continue
				}
				t.Errorf("fixture %s contains what looks like a %s: %q\n"+
					"Fixtures are committed to the repository; sanitize before adding.", path, f.name, redact(m))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk fixtures: %v", err)
	}
}

func hasAllowedDomain(email string) bool {
	lower := strings.ToLower(email)
	for _, d := range allowedEmailDomains {
		if strings.HasSuffix(lower, d) {
			return true
		}
	}
	return false
}

// redact keeps the failure message useful without reprinting the whole secret
// into CI logs, which would defeat the purpose of the check.
func redact(s string) string {
	if len(s) <= 8 {
		return "********"
	}
	return s[:4] + "..." + s[len(s)-2:]
}

func TestLuhnDistinguishesCardsFromIdentifiers(t *testing.T) {
	// A real (test-issuer) card number must still be caught...
	if !luhn("4111111111111111") {
		t.Error("a valid card number must pass Luhn and therefore be flagged")
	}
	// ...while an F5 ASM support_id, which matches the Visa regex by shape,
	// must not produce a false positive that trains people to ignore the guard.
	if luhn("4823905718293847") {
		t.Error("this F5 support_id happens to pass Luhn; pick another fixture value")
	}
}
