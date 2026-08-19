package normalize

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"

	"github.com/menta2k/siem-v2/backend/internal/normalize/schema"
)

// Classification describes how sensitive a field is.
type Classification string

const (
	// Public fields are safe for anyone who may see the flow at all.
	Public Classification = "public"
	// Sensitive fields are masked unless the viewer holds view_sensitive.
	Sensitive Classification = "sensitive"
	// Secret fields are NEVER stored in readable form, for anyone. A credential
	// that reaches storage is a credential that has leaked, regardless of who
	// can read it afterwards.
	Secret Classification = "secret"
)

// headerClassification classifies request and response headers by name.
//
// The list is deliberately conservative: a header that might carry a credential
// is treated as one. Under-classifying stores a secret forever; over-classifying
// costs an analyst one permission check.
var headerClassification = map[string]Classification{
	"authorization":       Secret,
	"proxy-authorization": Secret,
	"cookie":              Secret,
	"set-cookie":          Secret,
	"x-api-key":           Secret,
	"x-auth-token":        Secret,
	"x-csrf-token":        Secret,
	"x-datadome-clientid": Sensitive,
	"x-forwarded-for":     Sensitive,
	"referer":             Sensitive,
	"user-agent":          Public,
	"host":                Public,
	"accept":              Public,
	"content-type":        Public,
	"cf-ray":              Public,
}

// valuePatterns catch secrets that appear in fields not classified by name —
// a token in a query string, for instance.
var valuePatterns = []struct {
	name    string
	pattern *regexp.Regexp
}{
	{"jwt", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`)},
	{"aws_key", regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)},
	{"bearer", regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._~+/-]{20,}=*`)},
	{"private_key", regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`)},
}

// Masker classifies and masks fields before storage.
//
// Masking happens at NORMALIZATION, before anything is written — not at read
// time. A secret masked only on the way out is still a secret sitting in the
// store, readable by anyone with database access and preserved for the whole
// retention period (FR-015).
type Masker struct {
	// tokenKey turns a sensitive value into a stable pseudonym, so an analyst can
	// still correlate "the same cookie appeared on these ten requests" without
	// ever seeing the cookie. An empty key means plain redaction.
	tokenKey []byte
}

func NewMasker(tokenKey []byte) *Masker { return &Masker{tokenKey: tokenKey} }

// ClassifyHeader returns a header's classification, defaulting to Sensitive.
//
// Unknown headers default to sensitive rather than public: a header nobody has
// classified is a header nobody has checked, and defaulting to visible is how
// custom auth headers end up in storage.
func ClassifyHeader(name string) Classification {
	if c, ok := headerClassification[strings.ToLower(strings.TrimSpace(name))]; ok {
		return c
	}
	return Sensitive
}

// Apply masks an event in place and records what was masked.
func (m *Masker) Apply(e *schema.Event) {
	if e == nil {
		return
	}
	var masked []string

	for name, value := range e.Request.Headers {
		switch ClassifyHeader(name) {
		case Secret:
			// Replaced entirely. The name is retained so an analyst can see the
			// header was present without seeing what it held.
			e.Request.Headers[name] = "[redacted]"
			masked = append(masked, "request.headers."+strings.ToLower(name))
		case Sensitive:
			e.Request.Headers[name] = m.tokenize(value)
			masked = append(masked, "request.headers."+strings.ToLower(name))
		}
	}

	if redacted, found := m.redactPatterns(e.Request.Query); found {
		e.Request.Query = redacted
		masked = append(masked, "request.query")
	}
	if redacted, found := m.redactPatterns(e.Request.Path); found {
		e.Request.Path = redacted
		masked = append(masked, "request.path")
	}

	if len(masked) > 0 {
		e.MaskedFields = append(e.MaskedFields, masked...)
		// The flag matters as much as the masking: a viewer must be able to tell
		// that what they are reading is incomplete (FR-070).
		e.AddFlag(schema.FlagFieldsMasked)
	}
}

// tokenize produces a stable pseudonym for a sensitive value.
func (m *Masker) tokenize(value string) string {
	if value == "" {
		return ""
	}
	if len(m.tokenKey) == 0 {
		return "[masked]"
	}
	mac := hmac.New(sha256.New, m.tokenKey)
	mac.Write([]byte(value))
	return "tok_" + hex.EncodeToString(mac.Sum(nil)[:8])
}

// redactPatterns replaces secret-shaped substrings anywhere in a value.
func (m *Masker) redactPatterns(value string) (string, bool) {
	if value == "" {
		return value, false
	}
	found := false
	out := value
	for _, p := range valuePatterns {
		if p.pattern.MatchString(out) {
			out = p.pattern.ReplaceAllString(out, "[redacted:"+p.name+"]")
			found = true
		}
	}
	return out, found
}
