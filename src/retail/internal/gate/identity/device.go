package identity

import (
	"crypto/subtle"
	"crypto/x509"
	"fmt"
	"strings"
)

// CertificateFingerprint returns the SHA-256 hex of the certificate DER. The gate
// binds a user to the exact client certificate presented over mTLS.
func CertificateFingerprint(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	return FingerprintFromDER(cert.Raw)
}

// DeviceMatches reports whether the presented fingerprint is one of the user's
// bound devices. An empty binding list means "no device restriction"; a bound user
// without a presented certificate never matches.
func DeviceMatches(fingerprints []string, presented string) bool {
	if len(fingerprints) == 0 {
		return true
	}
	presented = strings.ToLower(strings.TrimSpace(presented))
	if len(presented) != 64 {
		return false
	}
	match := 0
	for _, candidate := range fingerprints {
		normalized := strings.ToLower(strings.TrimSpace(candidate))
		if len(normalized) != len(presented) {
			continue
		}
		match |= subtle.ConstantTimeCompare([]byte(normalized), []byte(presented))
	}
	return match == 1
}

// ValidateFingerprint reports whether value is a lowercase SHA-256 hex digest.
func ValidateFingerprint(value string) error {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if len(normalized) != 64 {
		return fmt.Errorf("identity: device fingerprint must be 64 hex characters")
	}
	for i := 0; i < len(normalized); i++ {
		switch c := normalized[i]; {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
		default:
			return fmt.Errorf("identity: device fingerprint is not hex")
		}
	}
	return nil
}
