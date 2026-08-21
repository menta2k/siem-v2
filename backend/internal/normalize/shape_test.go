package normalize

import (
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
