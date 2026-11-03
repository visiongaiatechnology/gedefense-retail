package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sync"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
)

// Store errors. Every corruption maps onto ErrCorruptState so the composition root
// can fail-closed on a single sentinel.
var (
	// ErrCorruptState reports persisted state that does not verify.
	ErrCorruptState = errors.New("gate store: persisted state is corrupt")
	// ErrClosed reports use after Close.
	ErrClosed = errors.New("gate store: store is closed")
	// ErrInvalidID reports a malformed identifier used as a document name.
	ErrInvalidID = errors.New("gate store: invalid identifier")
)

// Directories below the data directory (contract §6).
const (
	plansDirName    = "plans"
	ordersDirName   = "orders"
	sessionsDirName = "sessions"
	deniesDirName   = "denies"
	auditDirName    = "audit"
	totpStepsName   = "totp-steps.json"
)

// DefaultRetention is the documented retention window in days.
type Retention struct {
	PlanDays  int
	DenyDays  int
	AuditDays int
}

// DefaultRetention returns Denies 180 days, Audit 365 days, Plans 365 days.
func DefaultRetention() Retention {
	return Retention{PlanDays: 365, DenyDays: 180, AuditDays: 365}
}

// Options configures the store.
type Options struct {
	Dir       string
	Clock     ports.Clock
	Retention Retention
}

// PruneResult reports how many documents a retention run removed.
type PruneResult struct {
	Plans    int `json:"plans"`
	Tokens   int `json:"tokens"`
	Sessions int `json:"sessions"`
	Denies   int `json:"denies"`
}

// Store is the persistent gate state.
type Store struct {
	dir       string
	clock     ports.Clock
	retention Retention
	chain     *auditChain

	mu         sync.Mutex
	steps      map[domain.GateUserID]int64
	stepsReady bool
	closed     bool
}

// Open creates the store layout, verifies the audit chain and validates every
// persisted document. A broken chain or an invalid document prevents startup.
func Open(opts Options) (*Store, error) {
	if opts.Dir == "" {
		return nil, fmt.Errorf("gate store: Dir is required")
	}
	clock := opts.Clock
	if clock == nil {
		clock = wallClock{}
	}
	retention := opts.Retention
	if retention.PlanDays == 0 {
		retention.PlanDays = 365
	}
	if retention.DenyDays == 0 {
		retention.DenyDays = 180
	}
	if retention.AuditDays == 0 {
		retention.AuditDays = 365
	}
	if retention.PlanDays < 1 || retention.DenyDays < 1 || retention.AuditDays < 1 {
		return nil, fmt.Errorf("gate store: retention days must be >= 1")
	}

	store := &Store{
		dir:       filepath.Clean(opts.Dir),
		clock:     clock,
		retention: retention,
	}
	dirs := []string{
		store.dir,
		filepath.Join(store.dir, plansDirName),
		filepath.Join(store.dir, ordersDirName),
		filepath.Join(store.dir, sessionsDirName),
		filepath.Join(store.dir, deniesDirName),
		filepath.Join(store.dir, auditDirName),
	}
	for _, dir := range dirs {
		if err := ensureDir(dir); err != nil {
			return nil, err
		}
	}

	chain, err := openAuditChain(filepath.Join(store.dir, auditDirName), clock)
	if err != nil {
		return nil, err
	}
	store.chain = chain
	if err := store.validateExistingState(); err != nil {
		return nil, err
	}
	return store, nil
}

// validateExistingState loads and validates every persisted document so a corrupt
// store never starts half-trusted.
func (s *Store) validateExistingState() error {
	plans, err := s.ListPlans(context.Background())
	if err != nil {
		return err
	}
	for _, plan := range plans {
		if verr := plan.Validate(); verr != nil {
			return fmt.Errorf("%w: plan %q: %v", ErrCorruptState, plan.PlanID, verr)
		}
		hash, herr := plan.ComputePlanHash()
		if herr != nil || hash != plan.PlanHash {
			return fmt.Errorf("%w: plan %q hash mismatch", ErrCorruptState, plan.PlanID)
		}
	}
	tokens, err := s.ListTokens(context.Background())
	if err != nil {
		return err
	}
	for _, token := range tokens {
		if verr := token.Validate(); verr != nil {
			return fmt.Errorf("%w: token %q: %v", ErrCorruptState, token.TokenID, verr)
		}
	}
	sessions, err := s.ListSessions(context.Background())
	if err != nil {
		return err
	}
	for _, session := range sessions {
		if verr := session.Validate(); verr != nil {
			return fmt.Errorf("%w: session %q: %v", ErrCorruptState, session.SessionID, verr)
		}
	}
	denies, err := s.ListDenies(context.Background(), 0)
	if err != nil {
		return err
	}
	for _, deny := range denies {
		if verr := deny.Validate(); verr != nil {
			return fmt.Errorf("%w: deny %q: %v", ErrCorruptState, deny.DenyID, verr)
		}
	}
	return nil
}

// Dir returns the data directory of the store.
func (s *Store) Dir() string { return s.dir }

// Close marks the store closed.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

// ensureOpen rejects use after shutdown.
func (s *Store) ensureOpen() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	return nil
}

// Prune removes terminal plans, old tokens, old sessions and old deny records
// according to the retention window. Every deletion run is audited first; the
// audit trail itself is never deleted by the retention window because truncating
// the hash chain prefix would make it unverifiable (documented in the contract).
func (s *Store) Prune(ctx context.Context, now time.Time) (PruneResult, error) {
	if err := s.ensureOpen(); err != nil {
		return PruneResult{}, err
	}
	now = now.UTC()
	cutoff := now.AddDate(0, 0, -s.retention.PlanDays)
	denyCutoff := now.AddDate(0, 0, -s.retention.DenyDays)

	plans, err := s.ListPlans(ctx)
	if err != nil {
		return PruneResult{}, err
	}
	tokens, err := s.ListTokens(ctx)
	if err != nil {
		return PruneResult{}, err
	}
	sessions, err := s.ListSessions(ctx)
	if err != nil {
		return PruneResult{}, err
	}
	denies, err := s.ListDenies(ctx, 0)
	if err != nil {
		return PruneResult{}, err
	}

	// Collect the candidates first, audit the intent, then delete. The gate never
	// deletes evidence without a preceding hash-chained entry (audit before
	// mutation), and the audit trail itself is never pruned.
	var planPaths, tokenPaths, sessionPaths, denyPaths []string
	for _, plan := range plans {
		if terminalPlanState(plan.State) && !plan.UpdatedAt.After(cutoff) {
			planPaths = append(planPaths, filepath.Join(s.dir, plansDirName, string(plan.PlanID)+".json"))
		}
	}
	for _, token := range tokens {
		if token.CreatedAt.Before(cutoff) || !token.ExpiresAt.After(now) || token.Revoked {
			tokenPaths = append(tokenPaths, filepath.Join(s.dir, ordersDirName, string(token.TokenID)+".json"))
		}
	}
	for _, session := range sessions {
		if session.CreatedAt.Before(cutoff) || !session.ExpiresAt.After(now) || session.Revoked {
			sessionPaths = append(sessionPaths, filepath.Join(s.dir, sessionsDirName, string(session.SessionID)+".json"))
		}
	}
	for _, deny := range denies {
		if deny.At.Before(denyCutoff) {
			denyPaths = append(denyPaths, filepath.Join(s.dir, deniesDirName, string(deny.DenyID)+".json"))
		}
	}

	result := PruneResult{
		Plans:    len(planPaths),
		Tokens:   len(tokenPaths),
		Sessions: len(sessionPaths),
		Denies:   len(denyPaths),
	}
	if result == (PruneResult{}) {
		return result, nil
	}
	if _, aerr := s.AppendAudit(ctx, domain.AuditEntry{
		At:         now,
		Actor:      "system",
		Role:       "system",
		Action:     "gate.store.prune",
		ObjectType: "gate_store",
		ObjectID:   "retention",
		Reason:     fmt.Sprintf("plans=%d tokens=%d sessions=%d denies=%d", result.Plans, result.Tokens, result.Sessions, result.Denies),
	}); aerr != nil {
		return PruneResult{}, fmt.Errorf("gate store: audit prune: %w", aerr)
	}
	for _, group := range [][]string{planPaths, tokenPaths, sessionPaths, denyPaths} {
		for _, path := range group {
			if rerr := removeDocument(path); rerr != nil {
				return result, rerr
			}
		}
	}
	return result, nil
}

// terminalPlanState reports whether a plan can no longer be acted on.
func terminalPlanState(state domain.WritePlanState) bool {
	switch state {
	case domain.PlanExecuted, domain.PlanExpired, domain.PlanRejected, domain.PlanCancelled:
		return true
	}
	return false
}

// LoadTOTPSteps returns the persisted highest accepted TOTP step per user.
func (s *Store) LoadTOTPSteps(ctx context.Context) (map[domain.GateUserID]int64, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stepsReady {
		out := make(map[domain.GateUserID]int64, len(s.steps))
		for user, step := range s.steps {
			out[user] = step
		}
		return out, nil
	}
	steps, err := s.loadTOTPStepsLocked()
	if err != nil {
		return nil, err
	}
	s.steps = steps
	s.stepsReady = true
	out := make(map[domain.GateUserID]int64, len(steps))
	for user, step := range steps {
		out[user] = step
	}
	return out, nil
}

// SaveTOTPStep persists one accepted TOTP step (fail-closed for the caller).
func (s *Store) SaveTOTPStep(ctx context.Context, user domain.GateUserID, step int64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := user.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidID, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	if !s.stepsReady {
		steps, err := s.loadTOTPStepsLocked()
		if err != nil {
			return err
		}
		s.steps = steps
		s.stepsReady = true
	}
	if existing, ok := s.steps[user]; ok && step <= existing {
		return nil
	}
	s.steps[user] = step
	return s.writeTOTPStepsLocked()
}

// totpStepsDocument is the on-disk form of the replay state.
type totpStepsDocument struct {
	Steps map[string]int64 `json:"steps"`
}

// loadTOTPStepsLocked reads the replay state document.
func (s *Store) loadTOTPStepsLocked() (map[domain.GateUserID]int64, error) {
	path := filepath.Join(s.dir, totpStepsName)
	raw, err := readDocument(path, maxStateDocBytes)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return make(map[domain.GateUserID]int64), nil
		}
		return nil, fmt.Errorf("gate store: read TOTP replay state: %w", err)
	}
	var document totpStepsDocument
	if derr := decodeStrict(raw, &document); derr != nil {
		return nil, fmt.Errorf("%w: TOTP replay state: %v", ErrCorruptState, derr)
	}
	steps := make(map[domain.GateUserID]int64, len(document.Steps))
	for user, step := range document.Steps {
		id := domain.GateUserID(user)
		if err := id.Validate(); err != nil || step <= 0 {
			return nil, fmt.Errorf("%w: invalid TOTP replay entry", ErrCorruptState)
		}
		steps[id] = step
	}
	return steps, nil
}

// writeTOTPStepsLocked persists the replay state atomically.
func (s *Store) writeTOTPStepsLocked() error {
	document := totpStepsDocument{Steps: make(map[string]int64, len(s.steps))}
	for user, step := range s.steps {
		document.Steps[string(user)] = step
	}
	raw, err := json.Marshal(document)
	if err != nil {
		return fmt.Errorf("gate store: marshal TOTP replay state: %w", err)
	}
	return writeFileAtomic(filepath.Join(s.dir, totpStepsName), append(raw, '\n'))
}
