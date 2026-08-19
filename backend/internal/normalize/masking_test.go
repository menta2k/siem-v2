package normalize

import (
	"strings"
	"testing"

	"github.com/menta2k/siem-v2/backend/internal/normalize/schema"
)

func eventWithHeaders(h map[string]string) *schema.Event {
	return &schema.Event{Request: schema.Request{Headers: h}}
}

// TestSecretsAreRedactedNotTokenized: a credential must not survive storage in
// ANY reversible or correlatable form. A stable pseudonym is still a handle on
// the secret, so secrets get replaced outright.
func TestSecretsAreRedactedNotTokenized(t *testing.T) {
	m := NewMasker([]byte("test-key"))
	e := eventWithHeaders(map[string]string{
		"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijklmnop",
		"Cookie":        "session=abc123; user=alice",
		"X-Api-Key":     "sk_live_9f8e7d6c5b4a",
	})
	m.Apply(e)

	for name, value := range e.Request.Headers {
		if value != "[redacted]" {
			t.Errorf("%s must be redacted outright, got %q", name, value)
		}
		if strings.Contains(value, "tok_") {
			t.Errorf("%s was tokenized; a pseudonym is still a handle on the secret", name)
		}
	}
	if !e.HasFlag(schema.FlagFieldsMasked) {
		t.Error("masking must be flagged so a viewer knows the record is incomplete")
	}
	if len(e.MaskedFields) != 3 {
		t.Errorf("every masked field must be named, got %v", e.MaskedFields)
	}
}

// TestSensitiveValuesAreTokenizedStably: an analyst must still be able to see
// "the same value appeared on these ten requests" without ever seeing the value.
func TestSensitiveValuesAreTokenizedStably(t *testing.T) {
	m := NewMasker([]byte("test-key"))

	a := eventWithHeaders(map[string]string{"X-Forwarded-For": "203.0.113.9"})
	b := eventWithHeaders(map[string]string{"X-Forwarded-For": "203.0.113.9"})
	c := eventWithHeaders(map[string]string{"X-Forwarded-For": "198.51.100.4"})
	m.Apply(a)
	m.Apply(b)
	m.Apply(c)

	av := a.Request.Headers["X-Forwarded-For"]
	bv := b.Request.Headers["X-Forwarded-For"]
	cv := c.Request.Headers["X-Forwarded-For"]

	if av != bv {
		t.Error("the same value must tokenize identically, or correlation is impossible")
	}
	if av == cv {
		t.Error("different values must tokenize differently")
	}
	if strings.Contains(av, "203.0.113.9") {
		t.Errorf("the original value leaked into the token: %q", av)
	}
}

// TestUnknownHeadersDefaultToSensitive: a header nobody classified is a header
// nobody checked. Defaulting to visible is how custom auth headers reach storage.
func TestUnknownHeadersDefaultToSensitive(t *testing.T) {
	if got := ClassifyHeader("X-Company-Internal-Token"); got != Sensitive {
		t.Errorf("an unclassified header must default to sensitive, got %q", got)
	}
	if got := ClassifyHeader("User-Agent"); got != Public {
		t.Errorf("an explicitly public header stays public, got %q", got)
	}
	// Classification is case-insensitive: providers do not agree on casing.
	if ClassifyHeader("AUTHORIZATION") != Secret || ClassifyHeader("authorization") != Secret {
		t.Error("classification must be case-insensitive")
	}
}

// TestSecretsInQueryStringsAreCaught covers the case name-based classification
// cannot: a token pasted into a URL.
func TestSecretsInQueryStringsAreCaught(t *testing.T) {
	m := NewMasker([]byte("test-key"))
	e := &schema.Event{Request: schema.Request{
		Path:  "/callback",
		Query: "code=abc&id_token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijklmnop",
	}}
	m.Apply(e)

	if strings.Contains(e.Request.Query, "eyJhbGci") {
		t.Errorf("a JWT in the query string must be redacted, got %q", e.Request.Query)
	}
	if !strings.Contains(e.Request.Query, "[redacted:jwt]") {
		t.Errorf("the redaction should name what was removed, got %q", e.Request.Query)
	}
	// The rest of the query survives: over-redacting destroys the evidence.
	if !strings.Contains(e.Request.Query, "code=abc") {
		t.Errorf("non-secret parameters must survive, got %q", e.Request.Query)
	}
}

func TestAWSKeyAndPrivateKeyPatterns(t *testing.T) {
	m := NewMasker(nil)
	for name, value := range map[string]string{
		"aws":         "key=AKIAIOSFODNN7EXAMPLE",
		"private_key": "-----BEGIN RSA PRIVATE KEY-----",
	} {
		out, found := m.redactPatterns(value)
		if !found {
			t.Errorf("%s pattern not caught in %q", name, value)
		}
		if strings.Contains(out, "AKIAIOSFODNN7EXAMPLE") || strings.Contains(out, "BEGIN RSA PRIVATE") {
			t.Errorf("%s survived redaction: %q", name, out)
		}
	}
}

// TestCleanEventIsNotFlagged: flagging every record would make the flag
// meaningless, and analysts would stop reading it.
func TestCleanEventIsNotFlagged(t *testing.T) {
	m := NewMasker([]byte("test-key"))
	e := eventWithHeaders(map[string]string{
		"User-Agent": "Mozilla/5.0", "Host": "shop.example.com", "Accept": "text/html",
	})
	m.Apply(e)

	if e.HasFlag(schema.FlagFieldsMasked) {
		t.Error("a record with nothing sensitive must not be flagged as masked")
	}
	if len(e.MaskedFields) != 0 {
		t.Errorf("nothing should be listed as masked, got %v", e.MaskedFields)
	}
	if e.Request.Headers["User-Agent"] != "Mozilla/5.0" {
		t.Error("public headers must pass through untouched")
	}
}

func TestNoKeyFallsBackToPlainMask(t *testing.T) {
	m := NewMasker(nil)
	e := eventWithHeaders(map[string]string{"X-Forwarded-For": "203.0.113.9"})
	m.Apply(e)
	if got := e.Request.Headers["X-Forwarded-For"]; got != "[masked]" {
		t.Errorf("without a token key the value is plainly masked, got %q", got)
	}
}

func TestNilEventIsSafe(t *testing.T) {
	NewMasker(nil).Apply(nil) // must not panic
}
