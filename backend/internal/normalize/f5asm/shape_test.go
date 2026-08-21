package f5asm

import "testing"

// TestShapeFromFixture: ASM's captured request text carries the FULL header
// block, so header count and bytes are real measurements. Total request bytes
// are deliberately absent — the capture truncates bodies, and a lying floor
// would understate the very ceiling the profiler learns.
func TestShapeFromFixture(t *testing.T) {
	e, err := New().Parse([]byte(lines(t)[0]), receivedAt)
	if err != nil {
		t.Fatal(err)
	}
	s := e.Shape
	if s == nil {
		t.Fatal("captured request must yield a shape")
	}
	// Host, CF-Ray, User-Agent, Cookie.
	if s.HeaderCount == nil || *s.HeaderCount != 4 {
		t.Fatalf("header count = %v, want 4", s.HeaderCount)
	}
	if s.HeaderBytes == nil || *s.HeaderBytes <= 0 {
		t.Fatalf("header bytes = %v, want measured", s.HeaderBytes)
	}
	if s.CookieCount == nil || *s.CookieCount != 2 {
		t.Fatalf("cookie count = %v, want 2", s.CookieCount)
	}
	if len(s.CookieNames) != 2 || s.CookieNames[0] != "TS01a" || s.CookieNames[1] != "session" {
		t.Fatalf("cookie names = %v", s.CookieNames)
	}
	if s.RequestBytes != nil {
		t.Fatalf("request bytes must stay nil for a truncated capture: %+v", s)
	}

	// Second record: Host + CF-Ray only, no cookie header.
	e2, err := New().Parse([]byte(lines(t)[1]), receivedAt)
	if err != nil {
		t.Fatal(err)
	}
	if e2.Shape == nil || e2.Shape.HeaderCount == nil || *e2.Shape.HeaderCount != 2 {
		t.Fatalf("record 2 shape = %+v, want header count 2", e2.Shape)
	}
	if e2.Shape.CookieCount != nil {
		t.Fatalf("record 2 has no cookie header: %+v", e2.Shape)
	}
}
