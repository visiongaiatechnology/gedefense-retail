package identity

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
)

// Errors returned by the identity service. The API layer maps them onto the
// documented HTTP codes; the service itself never decides status codes.
var (
	// ErrInvalidCredentials reports an unknown user or a wrong password/TOTP. It is
	// deliberately the same error for both so the API cannot be used as a user
	// oracle.
	ErrInvalidCredentials = errors.New("identity: invalid credentials")
	// ErrDeviceNotBound reports a failed mTLS device binding.
	ErrDeviceNotBound = errors.New("identity: device not bound")
	// ErrUserDisabled reports a disabled identity.
	ErrUserDisabled = errors.New("identity: user disabled")
	// ErrMFARequired reports a missing TOTP code where one is mandatory.
	ErrMFARequired = errors.New("identity: MFA required")
	// ErrLockedOut reports an active lockout window.
	ErrLockedOut = errors.New("identity: too many failed attempts")
	// ErrUnknownUser reports a missing identity on the management path.
	ErrUnknownUser = errors.New("identity: unknown user")
)

// StepStore persists the highest accepted TOTP step so replay protection survives
// a restart. It is optional for tests; the gate wires an on-disk implementation.
type StepStore interface {
	LoadTOTPSteps(ctx context.Context) (map[domain.GateUserID]int64, error)
	SaveTOTPStep(ctx context.Context, user domain.GateUserID, step int64) error
}

// Options configures the identity service.
type Options struct {
	Users      []domain.GateUser
	Clock      ports.Clock
	TOTPWindow int
	Lockout    LockoutPolicy
	Steps      StepStore
}

// LoginRequest is one credential verification attempt. DeviceFingerprint is empty
// when the connection has no client certificate.
type LoginRequest struct {
	UserID            string
	Password          string
	TOTP              string
	DeviceFingerprint string
	SourceIP          string
}

// LoginResult is the authenticated identity of a login.
type LoginResult struct {
	User   domain.GateUser
	MFAOK  bool
	LockAt time.Time
}

// wallClock is the default ports.Clock implementation.
type wallClock struct{}

func (wallClock) Now() time.Time { return time.Now().UTC() }

// Service verifies vendor/operator/admin credentials and MFA codes.
type Service struct {
	clock      ports.Clock
	users      map[domain.GateUserID]domain.GateUser
	order      []domain.GateUserID
	replay     *ReplayGuard
	lockout    *lockoutSet
	steps      StepStore
	totpWindow int
	dummyHash  string

	mu        sync.Mutex
	lastLogin map[domain.GateUserID]time.Time
}

// New builds the identity service from configured users.
func New(opts Options) (*Service, error) {
	if len(opts.Users) == 0 {
		return nil, fmt.Errorf("identity: at least one user is required")
	}
	clock := opts.Clock
	if clock == nil {
		clock = wallClock{}
	}
	window := opts.TOTPWindow
	if window < 0 {
		window = 0
	}
	if window == 0 {
		window = DefaultTOTPWindow
	}
	if window > totpMaxWindow {
		window = totpMaxWindow
	}

	service := &Service{
		clock:      clock,
		users:      make(map[domain.GateUserID]domain.GateUser, len(opts.Users)),
		order:      make([]domain.GateUserID, 0, len(opts.Users)),
		replay:     NewReplayGuard(),
		lockout:    newLockoutSet(opts.Lockout, clock.Now),
		steps:      opts.Steps,
		totpWindow: window,
		lastLogin:  make(map[domain.GateUserID]time.Time),
	}
	maxIterations := MinIterations
	for i, user := range opts.Users {
		if err := validateUser(user); err != nil {
			return nil, fmt.Errorf("identity: users[%d]: %w", i, err)
		}
		if _, dup := service.users[user.UserID]; dup {
			return nil, fmt.Errorf("identity: duplicate user_id %q", user.UserID)
		}
		if parsed, err := ParsePasswordHash(user.PasswordHash); err == nil && parsed.iterations > maxIterations {
			maxIterations = parsed.iterations
		}
		service.users[user.UserID] = user
		service.order = append(service.order, user.UserID)
	}
	// The dummy digest makes "unknown user" cost the same as "known user, wrong
	// password" and hides user existence from a timing oracle.
	dummy, err := HashPasswordWithIterations("dummy-credential-never-used", maxIterations)
	if err != nil {
		return nil, fmt.Errorf("identity: build timing dummy: %w", err)
	}
	service.dummyHash = dummy
	if opts.Steps != nil {
		steps, serr := opts.Steps.LoadTOTPSteps(context.Background())
		if serr != nil {
			return nil, fmt.Errorf("identity: load TOTP replay state: %w", serr)
		}
		for user, step := range steps {
			service.replay.Seed(user, step)
		}
	}
	sort.Slice(service.order, func(i, j int) bool { return service.order[i] < service.order[j] })
	return service, nil
}

// validateUser enforces the identity contract beyond the domain type.
func validateUser(user domain.GateUser) error {
	if err := user.Validate(); err != nil {
		return err
	}
	if err := ValidatePasswordHash(user.PasswordHash); err != nil {
		return err
	}
	if user.TOTPEnabled {
		if err := ValidateTOTPSecret(user.TOTPSecret); err != nil {
			return err
		}
	}
	for _, fingerprint := range user.DeviceFingerprints {
		if err := ValidateFingerprint(fingerprint); err != nil {
			return err
		}
	}
	return nil
}

// Now returns the service clock (UTC).
func (s *Service) Now() time.Time { return s.clock.Now().UTC() }

// User returns the full internal identity.
func (s *Service) User(id domain.GateUserID) (domain.GateUser, bool) {
	user, ok := s.users[id]
	return user, ok
}

// Users returns the public view of every identity (secrets cleared).
func (s *Service) Users() []domain.GateUser {
	out := make([]domain.GateUser, 0, len(s.order))
	for _, id := range s.order {
		user := s.users[id]
		user.PasswordHash = ""
		user.TOTPSecret = ""
		user.DeviceFingerprints = nil
		out = append(out, user)
	}
	return out
}

// LastLogin returns the in-memory last successful login of a user.
func (s *Service) LastLogin(id domain.GateUserID) time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastLogin[id]
}

// Authenticate verifies password, optional TOTP (with replay protection) and the
// mTLS device binding. Every failure path is counted for lockout.
func (s *Service) Authenticate(ctx context.Context, req LoginRequest) (LoginResult, error) {
	if err := ctx.Err(); err != nil {
		return LoginResult{}, err
	}
	userID := domain.GateUserID(strings.TrimSpace(req.UserID))
	key := string(userID) + "|" + req.SourceIP
	if _, locked := s.lockout.locked(key); locked {
		return LoginResult{}, ErrLockedOut
	}

	user, known := s.users[userID]
	if !known {
		// Constant work for an unknown user; the result is discarded.
		_, _ = VerifyPassword(s.dummyHash, req.Password)
		s.lockout.fail(key)
		return LoginResult{}, ErrInvalidCredentials
	}

	ok, err := VerifyPassword(user.PasswordHash, req.Password)
	if err != nil {
		return LoginResult{}, fmt.Errorf("identity: verify password: %w", err)
	}
	if !ok {
		s.lockout.fail(key)
		return LoginResult{}, ErrInvalidCredentials
	}
	if user.Status != domain.GateUserActive {
		s.lockout.fail(key)
		return LoginResult{}, ErrUserDisabled
	}

	mfaOK := false
	if user.TOTPEnabled {
		if strings.TrimSpace(req.TOTP) == "" {
			s.lockout.fail(key)
			return LoginResult{}, ErrMFARequired
		}
		if err := s.consumeTOTP(ctx, user, req.TOTP); err != nil {
			s.lockout.fail(key)
			return LoginResult{}, err
		}
		mfaOK = true
	}

	if !DeviceMatches(user.DeviceFingerprints, req.DeviceFingerprint) {
		s.lockout.fail(key)
		return LoginResult{}, ErrDeviceNotBound
	}

	s.lockout.reset(key)
	now := s.clock.Now().UTC()
	s.mu.Lock()
	s.lastLogin[userID] = now
	s.mu.Unlock()
	return LoginResult{User: user, MFAOK: mfaOK}, nil
}

// VerifyMFA verifies a fresh TOTP code for a step-up action (approval, policy
// reload). It enforces replay protection exactly like a login.
func (s *Service) VerifyMFA(ctx context.Context, userID domain.GateUserID, code string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	user, ok := s.users[userID]
	if !ok {
		return ErrInvalidCredentials
	}
	if !user.TOTPEnabled {
		return ErrMFARequired
	}
	if strings.TrimSpace(code) == "" {
		return ErrMFARequired
	}
	return s.consumeTOTP(ctx, user, code)
}

// consumeTOTP verifies the code, enforces replay protection and persists the
// accepted step (fail-closed when persistence fails).
func (s *Service) consumeTOTP(ctx context.Context, user domain.GateUser, code string) error {
	step, err := VerifyTOTP(user.TOTPSecret, strings.TrimSpace(code), s.clock.Now().UTC(), s.totpWindow)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidCredentials, err)
	}
	if step == 0 {
		return ErrInvalidCredentials
	}
	if !s.replay.Accept(user.UserID, step) {
		return ErrTOTPReplay
	}
	if s.steps != nil {
		if err := s.steps.SaveTOTPStep(ctx, user.UserID, step); err != nil {
			return fmt.Errorf("identity: persist TOTP replay state: %w", err)
		}
	}
	return nil
}

// RecordTOTPStep restores replay state from an external source (tests/CLI).
func (s *Service) RecordTOTPStep(user domain.GateUserID, step int64) bool {
	return s.replay.Accept(user, step)
}
