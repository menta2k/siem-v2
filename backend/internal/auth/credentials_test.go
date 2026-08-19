package auth

import (
	"errors"
	"strings"
	"testing"
)

func TestPasswordRoundTrip(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$") {
		t.Errorf("hash should be PHC-encoded argon2id, got %q", hash[:20])
	}
	if err := VerifyPassword("correct horse battery staple", hash); err != nil {
		t.Errorf("the right password must verify: %v", err)
	}
	if err := VerifyPassword("wrong password", hash); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("a wrong password must return ErrInvalidCredentials, got %v", err)
	}
}

// TestSameSaltNeverReused: two hashes of one password must differ, or a stolen
// table reveals which users share passwords.
func TestSameSaltNeverReused(t *testing.T) {
	a, _ := HashPassword("password-of-length")
	b, _ := HashPassword("password-of-length")
	if a == b {
		t.Fatal("two hashes of the same password must use different salts")
	}
}

func TestMalformedHashIsCorruptionNotWrongPassword(t *testing.T) {
	for _, h := range []string{"", "nonsense", "$argon2i$v=19$m=1,t=1,p=1$c$k", "$argon2id$v=18$m=1,t=1,p=1$c$k"} {
		err := VerifyPassword("anything", h)
		if !errors.Is(err, ErrMalformedHash) {
			t.Errorf("hash %q: want ErrMalformedHash, got %v", h, err)
		}
	}
}

func TestNeedsRehashOnWeakerParams(t *testing.T) {
	current, _ := HashPassword("password-of-length")
	if NeedsRehash(current) {
		t.Error("a hash at current parameters does not need rehashing")
	}
	weak := "$argon2id$v=19$m=1024,t=1,p=1$c2FsdHNhbHRzYWx0c2FsdA$a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5"
	if !NeedsRehash(weak) {
		t.Error("a hash at weaker parameters must be flagged for upgrade")
	}
	if !NeedsRehash("garbage") {
		t.Error("an unparseable hash must be flagged")
	}
}

// TestDummyVerificationDoesNotPanic: the constant-time path for unknown users
// must be safe to call unconditionally.
func TestDummyVerificationDoesNotPanic(t *testing.T) {
	VerifyDummyPassword()
	VerifyDummyPassword() // idempotent
}

func TestEmptyPasswordRejected(t *testing.T) {
	if _, err := HashPassword(""); err == nil {
		t.Fatal("an empty password must not be hashable")
	}
}
