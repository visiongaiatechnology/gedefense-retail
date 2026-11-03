package api

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// idRandomBytes is the entropy of a generated identifier (128 bit).
const idRandomBytes = 16

// newPrefixedID creates an unpredictable identifier with the given prefix.
func newPrefixedID(prefix string) (string, error) {
	raw := make([]byte, idRandomBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("api: generate id: %w", err)
	}
	return prefix + hex.EncodeToString(raw), nil
}
