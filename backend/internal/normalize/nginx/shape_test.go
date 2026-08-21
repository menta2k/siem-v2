package nginx

import "testing"

// TestShapeFromFixture: $request_length is nginx's own request total, and the
// opt-in $http_cookie field is reduced to a count and names — the values never
// reach the event.
func TestShapeFromFixture(t *testing.T) {
	fixture := lines(t)
	p := New()

	bytesOnly, err := p.Parse([]byte(fixture[0]), receivedAt)
	if err != nil {
		t.Fatal(err)
	}
	if bytesOnly.Shape == nil || bytesOnly.Shape.RequestBytes == nil || *bytesOnly.Shape.RequestBytes != 412 {
		t.Fatalf("shape = %+v, want request bytes 412", bytesOnly.Shape)
	}
	if bytesOnly.Shape.CookieCount != nil {
		t.Fatalf("no http_cookie shipped, count must be nil: %+v", bytesOnly.Shape)
	}
	// Headers are never shipped by the nginx log format.
	if bytesOnly.Shape.HeaderCount != nil {
		t.Fatalf("header count must be nil for nginx: %+v", bytesOnly.Shape)
	}

	withCookie, err := p.Parse([]byte(fixture[1]), receivedAt)
	if err != nil {
		t.Fatal(err)
	}
	s := withCookie.Shape
	if s == nil || s.CookieCount == nil || *s.CookieCount != 2 {
		t.Fatalf("shape = %+v, want cookie count 2", s)
	}
	if len(s.CookieNames) != 2 || s.CookieNames[0] != "session" || s.CookieNames[1] != "cart_id" {
		t.Fatalf("cookie names = %v", s.CookieNames)
	}
	for _, n := range s.CookieNames {
		if n == "synthetic-fixture-value" || n == "42" {
			t.Fatal("a cookie VALUE leaked into the shape")
		}
	}
}
