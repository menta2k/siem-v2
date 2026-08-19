package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

// Sealing the TOTP secret so it can be written to PostgreSQL.
//
// The package rule is that a live shared secret is never persisted in the
// clear: the database is queried by every operator path and backed up to places
// with their own access control. What is stored is ciphertext; the key lives in
// the service's environment, which the database has no access to.

// SealerKeyBytes is the AES-256 key length this package requires.
const SealerKeyBytes = 32

// ErrSealerKeyRequired reports a sealer asked for without a key to seal with.
var ErrSealerKeyRequired = errors.New("auth: a 32-byte sealing key is required")

// Sealer encrypts and decrypts secrets with AES-256-GCM.
type Sealer struct {
	aead cipher.AEAD
}

// NewSealer builds a sealer from a raw 32-byte key.
func NewSealer(key []byte) (*Sealer, error) {
	if len(key) != SealerKeyBytes {
		return nil, fmt.Errorf("%w: got %d bytes", ErrSealerKeyRequired, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("auth: build cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("auth: build GCM: %w", err)
	}
	return &Sealer{aead: aead}, nil
}

// Seal encrypts a secret. Each call uses a fresh nonce, so sealing the same
// value twice produces different ciphertexts — equality of stored values must
// never reveal equality of secrets.
func (s *Sealer) Seal(plaintext string) (string, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("auth: generate nonce: %w", err)
	}
	sealed := s.aead.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.RawStdEncoding.EncodeToString(sealed), nil
}

// Open decrypts a sealed secret.
func (s *Sealer) Open(sealed string) (string, error) {
	raw, err := base64.RawStdEncoding.DecodeString(sealed)
	if err != nil {
		return "", fmt.Errorf("auth: undecodable sealed value: %w", err)
	}
	if len(raw) < s.aead.NonceSize() {
		return "", errors.New("auth: sealed value too short")
	}
	nonce, ciphertext := raw[:s.aead.NonceSize()], raw[s.aead.NonceSize():]
	plain, err := s.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		// One error for tamper, truncation and wrong key alike.
		return "", errors.New("auth: sealed value cannot be opened")
	}
	return string(plain), nil
}
