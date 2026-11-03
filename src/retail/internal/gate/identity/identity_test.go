package identity

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

type testClock struct{ now time.Time }

func (c *testClock) Now() time.Time { return c.now }

func newTestUser(t *testing.T, id string, roles []domain.GateRole, withTOTP bool) domain.GateUser {
	t.Helper()
	hash, err := HashPasswordWithIterations("a-strong-password", MinIterations)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	user := domain.GateUser{
		UserID: domain.GateUserID(id), Name: id, Kind: domain.GateUserOperator,
		Roles: roles, PasswordHash: hash, Status: domain.GateUserActive,
	}
	if withTOTP {
		secret, serr := NewTOTPSecret()
		if serr != nil {
			t.Fatalf("totp secret: %v", serr)
		}
		user.TOTPSecret = secret
		user.TOTPEnabled = true
	}
	return user
}

func TestPasswordHash(t *testing.T) {
	hash, err := HashPasswordWithIterations("correct horse battery", MinIterations)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if err := ValidatePasswordHash(hash); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if ok, _ := VerifyPassword(hash, "correct horse battery"); !ok {
		t.Fatal("correct password rejected")
	}
	if ok, _ := VerifyPassword(hash, "wrong password"); ok {
		t.Fatal("wrong password accepted")
	}
	for _, bad := range []string{"", "plain", "pbkdf2-sha256$1$AAAA$AAAA", "argon2id$x$y$z"} {
		if err := ValidatePasswordHash(bad); err == nil {
			t.Errorf("accepted malformed hash %q", bad)
		}
	}
	if _, err := HashPassword("short"); !errors.Is(err, ErrWeakPassword) {
		t.Errorf("short password error = %v", err)
	}
}

func TestTOTPAndReplay(t *testing.T) {
	secret, err := NewTOTPSecret()
	if err != nil {
		t.Fatalf("secret: %v", err)
	}
	at := time.Date(2026, 11, 3, 20, 0, 0, 0, time.UTC)
	code, err := TOTPCodeAt(secret, at)
	if err != nil {
		t.Fatalf("code: %v", err)
	}
	if len(code) != TOTPDigits {
		t.Fatalf("code = %q", code)
	}
	step, err := VerifyTOTP(secret, code, at, DefaultTOTPWindow)
	if err != nil || step != TOTPStep(at) {
		t.Fatalf("verify: step=%d err=%v", step, err)
	}
	if _, err := VerifyTOTP(secret, "abcdef", at, 1); !errors.Is(err, ErrInvalidTOTPCode) {
		t.Errorf("non-digit code error = %v", err)
	}
	guard := NewReplayGuard()
	if !guard.Accept("user-1", step) {
		t.Fatal("first use rejected")
	}
	if guard.Accept("user-1", step) {
		t.Fatal("replay accepted")
	}
	if !guard.Accept("user-1", step+1) {
		t.Fatal("newer step rejected")
	}
}

func TestDeviceBinding(t *testing.T) {
	fingerprint := FingerprintFromDER([]byte("certificate-der"))
	if err := ValidateFingerprint(fingerprint); err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	if !DeviceMatches(nil, "") {
		t.Error("unbound user must not require a device")
	}
	if !DeviceMatches([]string{fingerprint}, fingerprint) {
		t.Error("bound fingerprint rejected")
	}
	if DeviceMatches([]string{fingerprint}, "0badc0de") || DeviceMatches([]string{fingerprint}, "") {
		t.Error("mismatched fingerprint accepted")
	}
}

func TestAuthenticateAndLockout(t *testing.T) {
	clock := &testClock{now: time.Date(2026, 11, 3, 20, 0, 0, 0, time.UTC)}
	user := newTestUser(t, "vendor-acme", []domain.GateRole{domain.GateRoleVendorWriteRequester}, true)
	service, err := New(Options{Users: []domain.GateUser{user}, Clock: clock})
	if err != nil {
		t.Fatalf("identity service: %v", err)
	}
	code, err := TOTPCodeAt(user.TOTPSecret, clock.Now())
	if err != nil {
		t.Fatalf("code: %v", err)
	}
	result, err := service.Authenticate(context.Background(), LoginRequest{
		UserID: "vendor-acme", Password: "a-strong-password", TOTP: code, SourceIP: "10.0.0.5",
	})
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if !result.MFAOK || result.User.UserID != "vendor-acme" {
		t.Fatalf("result = %+v", result)
	}
	// A second login in the same time step is a TOTP replay.
	if _, err := service.Authenticate(context.Background(), LoginRequest{
		UserID: "vendor-acme", Password: "a-strong-password", TOTP: code, SourceIP: "10.0.0.5",
	}); !errors.Is(err, ErrTOTPReplay) {
		t.Fatalf("replay login error = %v", err)
	}
	// Unknown user and wrong password share one opaque error.
	if _, err := service.Authenticate(context.Background(), LoginRequest{UserID: "ghost", Password: "x", SourceIP: "10.9.9.9"}); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("unknown user error = %v", err)
	}
	for i := 0; i < 5; i++ {
		_, _ = service.Authenticate(context.Background(), LoginRequest{UserID: "vendor-acme", Password: "wrong", SourceIP: "10.0.0.5"})
	}
	if _, err := service.Authenticate(context.Background(), LoginRequest{UserID: "vendor-acme", Password: "a-strong-password", SourceIP: "10.0.0.5"}); !errors.Is(err, ErrLockedOut) {
		t.Errorf("lockout error = %v", err)
	}
}

func TestDeviceBoundLogin(t *testing.T) {
	clock := &testClock{now: time.Now().UTC()}
	user := newTestUser(t, "vendor-mtls", []domain.GateRole{domain.GateRoleVendorRead}, false)
	user.DeviceFingerprints = []string{FingerprintFromDER([]byte("device"))}
	service, err := New(Options{Users: []domain.GateUser{user}, Clock: clock})
	if err != nil {
		t.Fatalf("identity service: %v", err)
	}
	fingerprint := FingerprintFromDER([]byte("device"))
	if _, err := service.Authenticate(context.Background(), LoginRequest{
		UserID: "vendor-mtls", Password: "a-strong-password", SourceIP: "10.0.0.6", DeviceFingerprint: fingerprint,
	}); err != nil {
		t.Fatalf("bound login: %v", err)
	}
	if _, err := service.Authenticate(context.Background(), LoginRequest{
		UserID: "vendor-mtls", Password: "a-strong-password", SourceIP: "10.0.0.6",
	}); !errors.Is(err, ErrDeviceNotBound) {
		t.Errorf("missing device error = %v", err)
	}
}
