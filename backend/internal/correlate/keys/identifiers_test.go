package keys

import "testing"

func TestNewIdentifierRejectsAbsentValues(t *testing.T) {
	// Providers spell "no value" in many ways. Treating any of them as a real
	// identifier would union every record missing that field into one enormous
	// bogus flow — a failure that looks like wildly successful correlation.
	for _, v := range []string{"", "   ", "-", "NA", "n/a", "null", "NONE", "unknown", "0"} {
		if _, ok := NewIdentifier(NSRayID, v); ok {
			t.Errorf("value %q must not be usable as a join key", v)
		}
	}
	if id, ok := NewIdentifier(NSRayID, " 8f2a3b4c5d6e7f01 "); !ok || id.Value != "8f2a3b4c5d6e7f01" {
		t.Fatalf("expected trimmed valid identifier, got %+v ok=%v", id, ok)
	}
}

func TestIdentifierNamespacingPreventsCrossVendorCollision(t *testing.T) {
	// The same opaque string from two vendors must not merge two unrelated
	// requests.
	ray, _ := NewIdentifier(NSRayID, "abc123")
	dd, _ := NewIdentifier(NSDataDome, "abc123")
	if ray.String() == dd.String() {
		t.Fatal("identifiers from different vendors must not collide")
	}
}

func TestCanonicalIsOrderIndependent(t *testing.T) {
	a, _ := NewIdentifier(NSRayID, "zzz")
	b, _ := NewIdentifier(NSDataDome, "aaa")
	c, _ := NewIdentifier(NSF5, "mmm")

	first, ok1 := Canonical([]Identifier{a, b, c})
	second, ok2 := Canonical([]Identifier{c, a, b})
	third, ok3 := Canonical([]Identifier{b, c, a})
	if !ok1 || !ok2 || !ok3 {
		t.Fatal("expected a canonical value for a non-empty set")
	}
	if first != second || second != third {
		t.Fatalf("canonical id must not depend on discovery order: %q %q %q", first, second, third)
	}
	if _, ok := Canonical(nil); ok {
		t.Fatal("empty set has no canonical id")
	}
}
