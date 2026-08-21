package cloudflare

import "testing"

// TestShapeFromFixture: ClientRequestBytes and a captured Cookie header become
// structural facts; header counts stay ABSENT because RequestHeaders is a
// configured subset and counting a subset as "the headers" would understate a
// ceiling while claiming to measure it.
func TestShapeFromFixture(t *testing.T) {
	lines := loadLines(t, "../../../test/fixtures/cloudflare/http_requests_modern.ndjson")
	p := New()

	withCookie, err := p.Parse(lines[0], receivedAt)
	if err != nil {
		t.Fatal(err)
	}
	s := withCookie.Shape
	if s == nil {
		t.Fatal("record with ClientRequestBytes and a cookie header must carry a shape")
	}
	if s.RequestBytes == nil || *s.RequestBytes != 1187 {
		t.Fatalf("request bytes = %v, want 1187", s.RequestBytes)
	}
	if s.CookieCount == nil || *s.CookieCount != 3 {
		t.Fatalf("cookie count = %v, want 3", s.CookieCount)
	}
	if len(s.CookieNames) != 3 || s.CookieNames[0] != "session" {
		t.Fatalf("cookie names = %v", s.CookieNames)
	}
	for _, n := range s.CookieNames {
		if n == "synthetic-fixture-value" {
			t.Fatal("a cookie VALUE leaked into the shape")
		}
	}
	if s.HeaderCount != nil || s.HeaderBytes != nil {
		t.Fatalf("header counts must stay nil for a Logpush subset: %+v", s)
	}

	bytesOnly, err := p.Parse(lines[1], receivedAt)
	if err != nil {
		t.Fatal(err)
	}
	if bytesOnly.Shape == nil || bytesOnly.Shape.RequestBytes == nil || *bytesOnly.Shape.RequestBytes != 642 {
		t.Fatalf("record 1 shape = %+v, want request bytes 642", bytesOnly.Shape)
	}
	if bytesOnly.Shape.CookieCount != nil {
		t.Fatalf("no cookie header captured, count must be nil: %+v", bytesOnly.Shape)
	}

	noShape, err := p.Parse(lines[2], receivedAt)
	if err != nil {
		t.Fatal(err)
	}
	if noShape.Shape != nil {
		t.Fatalf("record without shape facts must carry none, got %+v", noShape.Shape)
	}
}
