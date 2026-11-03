package identity

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

const (
	// TOTPPeriodSeconds is the RFC 6238 time step.
	TOTPPeriodSeconds = 30
	// TOTPDigits is the number of decimal digits of a code.
	TOTPDigits = 6
	// DefaultTOTPWindow accepts the previous, current and next time step.
	DefaultTOTPWindow = 1

	totpSecretBytes = 20
	totpMaxWindow   = 3
)

// TOTP errors.
var (
	// ErrInvalidTOTPSecret reports a secret that is not valid Base32.
	ErrInvalidTOTPSecret = errors.New("identity: invalid TOTP secret")
	// ErrInvalidTOTPCode reports a code that is not six decimal digits.
	ErrInvalidTOTPCode = errors.New("identity: invalid TOTP code")
	// ErrTOTPReplay reports a code whose time step was already used.
	ErrTOTPReplay = errors.New("identity: TOTP code replay detected")
)

var totpBase32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret generates a fresh 160-bit Base32 secret.
func NewTOTPSecret() (string, error) {
	raw := make([]byte, totpSecretBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("identity: generate TOTP secret: %w", err)
	}
	return totpBase32.EncodeToString(raw), nil
}

// ValidateTOTPSecret reports whether secret is valid Base32.
func ValidateTOTPSecret(secret string) error {
	_, err := decodeTOTPSecret(secret)
	return err
}

// decodeTOTPSecret decodes a Base32 secret, tolerating missing padding.
func decodeTOTPSecret(secret string) ([]byte, error) {
	normalized := strings.ToUpper(strings.TrimSpace(secret))
	if normalized == "" {
		return nil, fmt.Errorf("%w: empty", ErrInvalidTOTPSecret)
	}
	normalized = strings.TrimRight(normalized, "=")
	raw, err := totpBase32.DecodeString(normalized)
	if err != nil || len(raw) < 10 || len(raw) > 64 {
		return nil, fmt.Errorf("%w: not valid Base32", ErrInvalidTOTPSecret)
	}
	return raw, nil
}

// TOTPStep returns the RFC 6238 time step of t.
func TOTPStep(at time.Time) int64 { return at.UTC().Unix() / TOTPPeriodSeconds }

// TOTPCodeAt computes the code for a secret at the given instant (CLI/tests).
func TOTPCodeAt(secret string, at time.Time) (string, error) {
	key, err := decodeTOTPSecret(secret)
	if err != nil {
		return "", err
	}
	return hotp(key, TOTPStep(at)), nil
}

// hotp computes the RFC 4226 six-digit value for one counter.
func hotp(key []byte, counter int64) string {
	mac := hmac.New(sha1.New, key)
	var message [8]byte
	binary.BigEndian.PutUint64(message[:], uint64(counter))
	mac.Write(message[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	binaryCode := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	code := binaryCode % 1000000
	return fmt.Sprintf("%06d", code)
}

// VerifyTOTP verifies code against secret at time at, accepting the configured
// number of adjacent time steps. It returns the matched step; 0 means no match.
func VerifyTOTP(secret, code string, at time.Time, window int) (int64, error) {
	key, err := decodeTOTPSecret(secret)
	if err != nil {
		return 0, err
	}
	if len(code) != TOTPDigits {
		return 0, fmt.Errorf("%w: expected %d digits", ErrInvalidTOTPCode, TOTPDigits)
	}
	for i := 0; i < len(code); i++ {
		if code[i] < '0' || code[i] > '9' {
			return 0, fmt.Errorf("%w: expected %d digits", ErrInvalidTOTPCode, TOTPDigits)
		}
	}
	if window < 0 {
		window = 0
	}
	if window > totpMaxWindow {
		window = totpMaxWindow
	}
	current := TOTPStep(at)
	for delta := -window; delta <= window; delta++ {
		expected := hotp(key, current+int64(delta))
		if subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 {
			return current + int64(delta), nil
		}
	}
	return 0, nil
}

// ReplayGuard remembers the highest accepted TOTP step per user so the same code
// cannot be used twice, including within the acceptance window.
type ReplayGuard struct {
	mu      sync.Mutex
	last    map[domain.GateUserID]int64
	maxSize int
}

// NewReplayGuard builds an empty replay guard.
func NewReplayGuard() *ReplayGuard {
	return &ReplayGuard{last: make(map[domain.GateUserID]int64), maxSize: 10000}
}

// Accept reports whether step is newer than the last accepted step for user and
// records it. A step equal to or older than the recorded one is a replay.
func (g *ReplayGuard) Accept(user domain.GateUserID, step int64) bool {
	if user == "" || step <= 0 {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if last, ok := g.last[user]; ok && step <= last {
		return false
	}
	if len(g.last) >= g.maxSize {
		// Bound the map without dropping security state silently: only prune
		// entries far behind the current epoch of the incoming user.
		for key, lastStep := range g.last {
			if lastStep < step-3600 {
				delete(g.last, key)
			}
		}
		if len(g.last) >= g.maxSize {
			return false
		}
	}
	g.last[user] = step
	return true
}

// Seed restores a persisted step without accepting a code (startup path).
func (g *ReplayGuard) Seed(user domain.GateUserID, step int64) {
	if user == "" || step <= 0 {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if last, ok := g.last[user]; !ok || step > last {
		g.last[user] = step
	}
}

// Last returns the recorded step of a user.
func (g *ReplayGuard) Last(user domain.GateUserID) (int64, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	step, ok := g.last[user]
	return step, ok
}
