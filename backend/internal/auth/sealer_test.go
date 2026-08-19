package auth

import (
	"strings"
	"testing"
)

var sealKey = []byte("0123456789abcdef0123456789abcdef")

func TestSealerRoundTrip(t *testing.T) {
	s, err := NewSealer(sealKey)
	if err != nil {
		t.Fatalf("sealer: %v", err)
	}
	sealed, err := s.Seal("JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if strings.Contains(sealed, "JBSWY3DP") {
		t.Fatal("the plaintext survived sealing")
	}
	got, err := s.Open(sealed)
	if err != nil || got != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("open: %q, %v", got, err)
	}
}

// TestSealingIsNonDeterministic: equality of stored values must never reveal
// equality of secrets.
func TestSealingIsNonDeterministic(t *testing.T) {
	s, _ := NewSealer(sealKey)
	a, _ := s.Seal("same-secret")
	b, _ := s.Seal("same-secret")
	if a == b {
		t.Fatal("sealing the same value twice must produce different ciphertexts")
	}
}

func TestTamperAndWrongKeyAreOneError(t *testing.T) {
	s, _ := NewSealer(sealKey)
	sealed, _ := s.Seal("secret")

	tampered := "A" + sealed[1:]
	if _, err := s.Open(tampered); err == nil {
		t.Fatal("a tampered value must not open")
	}

	other, _ := NewSealer([]byte("ffffffffffffffffffffffffffffffff"))
	if _, err := other.Open(sealed); err == nil {
		t.Fatal("the wrong key must not open the value")
	}
	if _, err := s.Open("!!!"); err == nil {
		t.Fatal("garbage must not open")
	}
}

func TestSealerRequires32Bytes(t *testing.T) {
	if _, err := NewSealer([]byte("short")); err == nil {
		t.Fatal("a short key must be refused")
	}
}
