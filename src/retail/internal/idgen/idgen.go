// Package idgen creates unpredictable, prefixed identifiers for events, alerts,
// incidents and sessions. Identifiers are never derived from counters or time:
// they must not leak volume, ordering or clock information.
package idgen

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
)

// New returns "<prefix>_<32 hex chars>" using crypto/rand. It panics only on a
// broken system RNG (a process-fatal condition that Go's crypto/rand itself
// reports), never on user input.
func New(prefix string) string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("idgen: crypto/rand unavailable: %v", err))
	}
	return prefix + "_" + hex.EncodeToString(b[:])
}

// ValidPrefix reports whether a caller-supplied prefix is acceptable for an ID.
// Prefixes are compile-time constants in this repository, but the check keeps
// future call sites honest.
func ValidPrefix(prefix string) bool {
	if prefix == "" || len(prefix) > 16 {
		return false
	}
	for _, r := range prefix {
		if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

// NormalizePrefix lowercases and strips an optional trailing underscore so that
// callers may pass either "alr" or "alr_".
func NormalizePrefix(prefix string) string {
	return strings.TrimSuffix(strings.ToLower(prefix), "_")
}
