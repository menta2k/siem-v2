package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// ErrInvalidMFACode is the single error for every MFA verification failure, so
// the endpoint cannot be used to distinguish "wrong code" from "no enrolment".
var ErrInvalidMFACode = errors.New("auth: invalid MFA code")

// totpSkew is how many 30-second periods either side of now are accepted, to
// absorb clock drift between the server and an authenticator app. Widening this
// trades security for convenience: each extra period is another valid code an
// attacker may guess.
const totpSkew = 1

// MFASecret is a freshly generated TOTP enrolment.
type MFASecret struct {
	// Secret is the base32 shared secret. It must be encrypted before storage
	// and must never appear in a log or an API response after enrolment
	// completes.
	Secret string
	// URI is the otpauth:// provisioning URI rendered as a QR code during
	// enrolment.
	URI string
}

// GenerateMFASecret creates a TOTP enrolment for a user.
func GenerateMFASecret(issuer, accountEmail string) (MFASecret, error) {
	if issuer == "" || accountEmail == "" {
		return MFASecret{}, errors.New("auth: issuer and account are required to generate an MFA secret")
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: accountEmail,
		Period:      30,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		return MFASecret{}, fmt.Errorf("generate TOTP secret: %w", err)
	}
	return MFASecret{Secret: key.Secret(), URI: key.URL()}, nil
}

// VerifyMFACode checks a TOTP code against a secret.
//
// Time is a parameter rather than read from the clock so this is
// deterministically testable — a validation function that silently depends on
// wall-clock time cannot be tested at a period boundary.
func VerifyMFACode(secret, code string, at time.Time) error {
	if secret == "" || code == "" {
		return ErrInvalidMFACode
	}

	valid, err := totp.ValidateCustom(code, secret, at, totp.ValidateOpts{
		Period:    30,
		Skew:      totpSkew,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil || !valid {
		return ErrInvalidMFACode
	}
	return nil
}

// GenerateMFACode produces the code valid at a given time. Used by tests and by
// the seed tool; it is never part of a request path.
func GenerateMFACode(secret string, at time.Time) (string, error) {
	code, err := totp.GenerateCodeCustom(secret, at, totp.ValidateOpts{
		Period:    30,
		Skew:      totpSkew,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		return "", fmt.Errorf("generate TOTP code: %w", err)
	}
	return code, nil
}
