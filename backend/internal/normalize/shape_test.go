package normalize

import (
	"net/url"
	"testing"

	"github.com/menta2k/siem-v2/backend/internal/normalize/schema"
)

func TestCookieShapeCountsNamesNeverValues(t *testing.T) {
	count, names := CookieShape("session=secret-value; _ga=GA1.2.3.4; flag")
	if count != 3 {
		t.Fatalf("count = %d, want 3", count)
	}
	want := []string{"session", "_ga", "flag"}
	for i, n := range names {
		if n != want[i] {
			t.Fatalf("names = %v, want %v", names, want)
		}
		if n == "secret-value" || n == "GA1.2.3.4" {
			t.Fatal("a cookie VALUE leaked into the names")
		}
	}
}

func TestCookieShapeEmptyHeader(t *testing.T) {
	if s := ShapeFromCookieHeader(nil, "  "); s != nil {
		t.Fatalf("blank header must not fabricate a shape: %+v", s)
	}
}

// TestMaskerLeavesShapeIntact: the whole point of computing shape at
// normalization is that masking afterwards destroys the cookie header value.
// The counts must survive what the values do not.
func TestMaskerLeavesShapeIntact(t *testing.T) {
	e := &schema.Event{
		Request: schema.Request{Headers: map[string]string{
			"cookie": "session=super-secret",
		}},
	}
	e.Shape = ShapeFromCookieHeader(nil, e.Request.Headers["cookie"])

	NewMasker(nil).Apply(e)

	if e.Request.Headers["cookie"] != "[redacted]" {
		t.Fatalf("cookie value must be redacted, got %q", e.Request.Headers["cookie"])
	}
	if e.Shape == nil || e.Shape.CookieCount == nil || *e.Shape.CookieCount != 1 {
		t.Fatalf("shape must survive masking: %+v", e.Shape)
	}
	if len(e.Shape.CookieNames) != 1 || e.Shape.CookieNames[0] != "session" {
		t.Fatalf("cookie names must survive masking: %v", e.Shape.CookieNames)
	}
}

func TestShapeFromBodyFormParsesNamesSecretFiltersValues(t *testing.T) {
	// A login POST: normal fields kept, the password blanked (name survives).
	body := "user=alice&page=2&password=hunter2SuperSecretToken1234567890abcd"
	s := ShapeFromBody(nil, "application/x-www-form-urlencoded", body)
	if s == nil || s.BodyForm == "" {
		t.Fatal("form body must yield BodyForm")
	}
	got, _ := parseForm(s.BodyForm)
	if got["user"] != "alice" || got["page"] != "2" {
		t.Fatalf("non-secret values not kept: %v", got)
	}
	if _, ok := got["password"]; !ok {
		t.Fatalf("password NAME must be kept: %v", got)
	}
	if got["password"] != "" {
		t.Fatalf("secret-looking value must be blanked, got %q", got["password"])
	}
}

func TestShapeFromBodyJSONTopLevelKeys(t *testing.T) {
	s := ShapeFromBody(nil, "application/json", `{"q":"engineer","limit":25,"nested":{"a":1}}`)
	if s == nil {
		t.Fatal("json body must yield a shape")
	}
	got, _ := parseForm(s.BodyForm)
	if got["q"] != "engineer" || got["limit"] != "25" {
		t.Fatalf("json scalars not captured: %v", got)
	}
	if _, ok := got["nested"]; !ok {
		t.Fatalf("nested key name must be present: %v", got)
	}
}

func TestShapeFromBodyIgnoresUnparseable(t *testing.T) {
	if s := ShapeFromBody(nil, "application/octet-stream", "\x00\x01binary"); s != nil {
		t.Fatalf("binary body must be ignored, got %+v", s)
	}
	if s := ShapeFromBody(nil, "application/json", "{not json"); s != nil {
		t.Fatalf("bad json must be ignored, got %+v", s)
	}
}

// parseForm is a tiny test helper over url.ParseQuery for flat assertions.
func parseForm(form string) (map[string]string, error) {
	vals, err := url.ParseQuery(form)
	out := map[string]string{}
	for k, vv := range vals {
		if len(vv) > 0 {
			out[k] = vv[0]
		} else {
			out[k] = ""
		}
	}
	return out, err
}
