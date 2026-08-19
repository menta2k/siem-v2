package auth

import (
	"errors"
	"strings"
	"testing"
	"time"
)

var mnow = time.Date(2026, 8, 19, 12, 0, 15, 0, time.UTC) // mid-period

func TestMFARoundTrip(t *testing.T) {
	secret, err := GenerateMFASecret("SIEM v2", "ana@acme.example.com")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if !strings.HasPrefix(secret.URI, "otpauth://totp/") {
		t.Errorf("provisioning URI should be otpauth://, got %q", secret.URI)
	}

	code, err := GenerateMFACode(secret.Secret, mnow)
	if err != nil {
		t.Fatalf("code: %v", err)
	}
	if err := VerifyMFACode(secret.Secret, code, mnow); err != nil {
		t.Errorf("the current code must verify: %v", err)
	}
}

// TestSkewAbsorbsOneAdjacentPeriod: an authenticator one period behind still
// works; one three periods behind does not.
func TestSkewAbsorbsOneAdjacentPeriod(t *testing.T) {
	secret, _ := GenerateMFASecret("SIEM v2", "ana@acme.example.com")

	previous, _ := GenerateMFACode(secret.Secret, mnow.Add(-30*time.Second))
	if err := VerifyMFACode(secret.Secret, previous, mnow); err != nil {
		t.Errorf("one period of drift is within the skew: %v", err)
	}

	stale, _ := GenerateMFACode(secret.Secret, mnow.Add(-3*30*time.Second))
	if err := VerifyMFACode(secret.Secret, stale, mnow); !errors.Is(err, ErrInvalidMFACode) {
		t.Errorf("three periods of drift must fail, got %v", err)
	}
}

func TestWrongAndEmptyCodesFail(t *testing.T) {
	secret, _ := GenerateMFASecret("SIEM v2", "ana@acme.example.com")
	for _, code := range []string{"", "000000", "12345"} {
		if err := VerifyMFACode(secret.Secret, code, mnow); !errors.Is(err, ErrInvalidMFACode) {
			t.Errorf("code %q must fail with the one coarse error, got %v", code, err)
		}
	}
	if err := VerifyMFACode("", "123456", mnow); !errors.Is(err, ErrInvalidMFACode) {
		t.Errorf("no enrolment must be indistinguishable from a wrong code, got %v", err)
	}
}
