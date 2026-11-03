// Package identity implements the Access Gate identity layer: PBKDF2-HMAC-SHA256
// password digests, RFC 6238 TOTP with replay protection, mTLS device binding,
// lockout thresholds and the small helpers the retailgate CLI needs for
// onboarding and rotation.
//
// Only the Go standard library is used. Passwords and TOTP secrets are never
// logged and never returned by the public user view.
package identity

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	// HashAlgorithm is the only accepted password hash scheme.
	HashAlgorithm = "pbkdf2-sha256"
	// DefaultIterations is the production PBKDF2 work factor.
	DefaultIterations = 210000
	// MinIterations / MaxIterations bound an accepted hash so a tampered
	// configuration can neither disable the work factor nor pin the CPU.
	MinIterations = 10000
	MaxIterations = 2000000

	saltBytes = 16
	keyBytes  = 32

	// MinPasswordLength is enforced when generating a hash (onboarding); existing
	// hashes are verified regardless of length.
	MinPasswordLength = 12
	maxPasswordLength = 1024
)

// ErrInvalidPasswordHash reports a malformed or unsupported password digest.
var ErrInvalidPasswordHash = errors.New("identity: invalid password hash format")

// ErrWeakPassword reports a password below the onboarding minimum length.
var ErrWeakPassword = errors.New("identity: password does not meet the minimum length")

// parsedPasswordHash is the decoded form of a stored digest.
type parsedPasswordHash struct {
	iterations int
	salt       []byte
	digest     []byte
}

// ParsePasswordHash decodes "pbkdf2-sha256$<iter>$<saltB64>$<hashB64>".
func ParsePasswordHash(encoded string) (parsedPasswordHash, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != HashAlgorithm {
		return parsedPasswordHash{}, fmt.Errorf("%w: expected %s$<iter>$<salt>$<hash>", ErrInvalidPasswordHash, HashAlgorithm)
	}
	iterations, err := strconv.Atoi(parts[1])
	if err != nil || iterations < MinIterations || iterations > MaxIterations {
		return parsedPasswordHash{}, fmt.Errorf("%w: iteration count outside [%d,%d]", ErrInvalidPasswordHash, MinIterations, MaxIterations)
	}
	salt, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil || len(salt) < saltBytes {
		return parsedPasswordHash{}, fmt.Errorf("%w: invalid salt", ErrInvalidPasswordHash)
	}
	digest, err := base64.StdEncoding.DecodeString(parts[3])
	if err != nil || len(digest) != keyBytes {
		return parsedPasswordHash{}, fmt.Errorf("%w: invalid digest", ErrInvalidPasswordHash)
	}
	return parsedPasswordHash{iterations: iterations, salt: salt, digest: digest}, nil
}

// ValidatePasswordHash reports whether encoded is an acceptable stored digest.
func ValidatePasswordHash(encoded string) error {
	_, err := ParsePasswordHash(encoded)
	return err
}

// HashPassword derives a production-work-factor digest for a new credential.
func HashPassword(password string) (string, error) {
	return HashPasswordWithIterations(password, DefaultIterations)
}

// HashPasswordWithIterations derives a digest with an explicit work factor. The
// iteration count is validated against the accepted range.
func HashPasswordWithIterations(password string, iterations int) (string, error) {
	if len(password) < MinPasswordLength {
		return "", fmt.Errorf("%w: at least %d characters", ErrWeakPassword, MinPasswordLength)
	}
	if len(password) > maxPasswordLength {
		return "", fmt.Errorf("%w: at most %d bytes", ErrWeakPassword, maxPasswordLength)
	}
	if iterations < MinIterations || iterations > MaxIterations {
		return "", fmt.Errorf("%w: iteration count outside [%d,%d]", ErrInvalidPasswordHash, MinIterations, MaxIterations)
	}
	salt := make([]byte, saltBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("identity: generate salt: %w", err)
	}
	digest := pbkdf2SHA256(password, salt, iterations)
	return fmt.Sprintf("%s$%d$%s$%s",
		HashAlgorithm,
		iterations,
		base64.StdEncoding.EncodeToString(salt),
		base64.StdEncoding.EncodeToString(digest),
	), nil
}

// VerifyPassword reports whether password matches the stored digest. The
// comparison of the derived key is constant time; a malformed digest yields an
// error, never a panic.
func VerifyPassword(encoded, password string) (bool, error) {
	parsed, err := ParsePasswordHash(encoded)
	if err != nil {
		return false, err
	}
	derived := pbkdf2SHA256(password, parsed.salt, parsed.iterations)
	return subtle.ConstantTimeCompare(derived, parsed.digest) == 1, nil
}

// pbkdf2SHA256 implements PBKDF2 (RFC 2898) with HMAC-SHA256 for a single output
// block (32 bytes). One block is exactly the stored key length, so no block
// counter loop is needed beyond the fixed first block.
func pbkdf2SHA256(password string, salt []byte, iterations int) []byte {
	mac := hmac.New(sha256.New, []byte(password))
	mac.Write(salt)
	mac.Write([]byte{0, 0, 0, 1})
	u := mac.Sum(nil)
	derived := make([]byte, len(u))
	copy(derived, u)
	for i := 1; i < iterations; i++ {
		mac.Reset()
		mac.Write(u)
		u = mac.Sum(u[:0])
		for j := range derived {
			derived[j] ^= u[j]
		}
	}
	return derived
}

// FingerprintFromDER returns the lowercase SHA-256 hex of a certificate DER.
func FingerprintFromDER(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}
