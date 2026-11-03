package approval

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/config"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
)

// sweepInterval bounds how often expired plans are re-evaluated; expiry is also
// forced on every mutation and on status/list reads.
const sweepInterval = 5 * time.Second

// Repository is the persistence seam consumed by the approval service. The store
// package implements it; the service never imports the store.
type Repository interface {
	SavePlan(ctx context.Context, plan domain.WritePlan) error
	GetPlan(ctx context.Context, id domain.PlanID) (domain.WritePlan, bool, error)
	ListPlans(ctx context.Context) ([]domain.WritePlan, error)
	SaveToken(ctx context.Context, token domain.WriteToken) error
	ListTokens(ctx context.Context) ([]domain.WriteToken, error)
	SaveSession(ctx context.Context, session domain.WriteSession) error
	ListSessions(ctx context.Context) ([]domain.WriteSession, error)
	AppendDeny(ctx context.Context, deny domain.DeniedWriteAttempt) error
	ListDenies(ctx context.Context, limit int) ([]domain.DeniedWriteAttempt, error)
	AppendAudit(ctx context.Context, entry domain.AuditEntry) (domain.AuditEntry, error)
	ListAudit(ctx context.Context, limit int) ([]domain.AuditEntry, error)
	VerifyAudit(ctx context.Context) (bool, uint64, error)
	AuditCount() int
	AuditFirstSeq() uint64
	SaveWriteUnknown(ctx context.Context, id string, document any) error
	ListWriteUnknown(ctx context.Context) ([][]byte, error)
	AppendEvent(ctx context.Context, event domain.GateEvent) error
}

// Options configures the approval service.
type Options struct {
	SiteID   domain.SiteID
	Clock    ports.Clock
	Repo     Repository
	Policy   func() config.Policy
	Target   func(domain.TargetID) (config.Target, bool)
	Timeouts config.Timeouts
	// Publish fans a gate event out to the API stream (optional).
	Publish func(domain.GateEvent)
	// Failsafe reports an active fail-safe (clock jump, store degradation, ...).
	Failsafe func() (bool, string)
	// IDFunc overrides identifier generation (tests). Production uses crypto/rand.
	IDFunc func(prefix string) (string, error)
}

// wallClock is the default ports.Clock implementation.
type wallClock struct{}

func (wallClock) Now() time.Time { return time.Now().UTC() }

// Service owns the write-plan lifecycle, one-time tokens, write sessions and the
// SessionLookup implementation used by the protocol proxies.
type Service struct {
	mu       sync.Mutex
	repo     Repository
	clock    ports.Clock
	policy   func() config.Policy
	targets  func(domain.TargetID) (config.Target, bool)
	timeouts config.Timeouts
	siteID   domain.SiteID
	publish  func(domain.GateEvent)
	failsafe func() (bool, string)
	idFunc   func(prefix string) (string, error)

	plans       map[domain.PlanID]domain.WritePlan
	tokens      map[domain.TokenID]domain.WriteToken
	tokenByHash map[string]domain.TokenID
	sessions    map[domain.SessionID]domain.WriteSession
	lastSweep   time.Time
}

// NewService loads the persisted state and expires stale plans (fail-closed when
// the repository or audit chain is unusable).
func NewService(opts Options) (*Service, error) {
	if opts.Repo == nil {
		return nil, fmt.Errorf("approval: repository is required")
	}
	if opts.Policy == nil || opts.Target == nil {
		return nil, fmt.Errorf("approval: policy and target lookup are required")
	}
	if err := opts.SiteID.Validate(); err != nil {
		return nil, fmt.Errorf("approval: site: %w", err)
	}
	clock := opts.Clock
	if clock == nil {
		clock = wallClock{}
	}
	idFunc := opts.IDFunc
	if idFunc == nil {
		idFunc = randomID
	}
	service := &Service{
		repo:        opts.Repo,
		clock:       clock,
		policy:      opts.Policy,
		targets:     opts.Target,
		timeouts:    opts.Timeouts,
		siteID:      opts.SiteID,
		publish:     opts.Publish,
		failsafe:    opts.Failsafe,
		idFunc:      idFunc,
		plans:       make(map[domain.PlanID]domain.WritePlan),
		tokens:      make(map[domain.TokenID]domain.WriteToken),
		tokenByHash: make(map[string]domain.TokenID),
		sessions:    make(map[domain.SessionID]domain.WriteSession),
	}
	ctx := context.Background()
	plans, err := opts.Repo.ListPlans(ctx)
	if err != nil {
		return nil, fmt.Errorf("approval: load plans: %w", err)
	}
	for _, plan := range plans {
		if verr := plan.Validate(); verr != nil {
			return nil, fmt.Errorf("approval: corrupt plan %q: %w", plan.PlanID, verr)
		}
		service.plans[plan.PlanID] = plan
	}
	tokens, err := opts.Repo.ListTokens(ctx)
	if err != nil {
		return nil, fmt.Errorf("approval: load tokens: %w", err)
	}
	for _, token := range tokens {
		if _, dup := service.tokenByHash[token.TokenHash]; dup {
			return nil, fmt.Errorf("approval: duplicate token hash in store")
		}
		service.tokens[token.TokenID] = token
		service.tokenByHash[token.TokenHash] = token.TokenID
	}
	sessions, err := opts.Repo.ListSessions(ctx)
	if err != nil {
		return nil, fmt.Errorf("approval: load sessions: %w", err)
	}
	for _, session := range sessions {
		service.sessions[session.SessionID] = session
	}
	service.lastSweep = clock.Now().UTC()
	if err := service.sweepLocked(ctx, true); err != nil {
		return nil, err
	}
	return service, nil
}

// Now returns the service clock (UTC).
func (s *Service) Now() time.Time { return s.clock.Now().UTC() }

// SiteID returns the configured site.
func (s *Service) SiteID() domain.SiteID { return s.siteID }

// Policy returns the currently active policy.
func (s *Service) Policy() config.Policy { return s.policy() }

// randomID creates a crypto-random prefixed identifier.
func randomID(prefix string) (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("approval: generate id: %w", err)
	}
	return prefix + hex.EncodeToString(raw), nil
}

// FailsafeState reports whether writes/sessions are currently denied by the
// fail-safe matrix and the stable deny reason the proxies must record
// (domain.DenyFailsafeClock, domain.DenyFailsafeStore, domain.DenyPolicyMissing, ...).
// The composition root wires this to internal/gate/failsafe Evaluate/CheckStartup.
func (s *Service) FailsafeState() (deny bool, reason string) {
	return s.failsafeActive()
}

// failsafeActive reports the fail-safe state.
func (s *Service) failsafeActive() (bool, string) {
	if s.failsafe == nil {
		return false, ""
	}
	return s.failsafe()
}

// recordAudit appends one hash-chained audit entry (audit before mutation).
func (s *Service) recordAudit(ctx context.Context, actor, role, action, objectType, objectID, reason string) error {
	if _, err := s.repo.AppendAudit(ctx, domain.AuditEntry{
		At:         s.clock.Now().UTC(),
		Actor:      actor,
		Role:       role,
		Action:     action,
		ObjectType: objectType,
		ObjectID:   objectID,
		Reason:     reason,
	}); err != nil {
		return fmt.Errorf("%w: audit %s: %v", ErrStore, action, err)
	}
	return nil
}

// RecordAudit is the API entry point for actions it owns (login, logout, policy
// reload). It never accepts secrets: callers pass only metadata.
func (s *Service) RecordAudit(ctx context.Context, actor, role, action, objectType, objectID, reason string) error {
	return s.recordAudit(ctx, actor, role, action, objectType, objectID, reason)
}

// emit publishes an event to the API stream and the optional export file. Neither
// is allowed to block or fail a gate mutation; failures are logged.
func (s *Service) emit(kind domain.GateEventKind, payload any) {
	raw, err := json.Marshal(payload)
	if err != nil {
		slog.Warn("gate event payload could not be encoded", "kind", string(kind), "error", err)
		return
	}
	event := domain.GateEvent{Kind: kind, At: s.clock.Now().UTC(), SiteID: s.siteID, Payload: raw}
	if s.publish != nil {
		func() {
			defer func() {
				if recovered := recover(); recovered != nil {
					slog.Error("gate event publisher panicked", "kind", string(kind), "panic", fmt.Sprint(recovered))
				}
			}()
			s.publish(event)
		}()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.repo.AppendEvent(ctx, event); err != nil {
		slog.Warn("gate event export failed", "kind", string(kind), "error", err)
	}
}

// sweepLocked expires plans whose window or approval TTL elapsed. It is called
// before every mutation and on read paths (rate limited by sweepInterval).
func (s *Service) sweepLocked(ctx context.Context, force bool) error {
	now := s.clock.Now().UTC()
	if !force && now.Sub(s.lastSweep) < sweepInterval {
		return nil
	}
	s.lastSweep = now
	policy := s.policy()
	for id, plan := range s.plans {
		expired := false
		switch plan.State {
		case domain.PlanPending:
			expired = !now.Before(plan.WindowEnd) || now.After(plan.RequestedAt.Add(s.timeouts.ApprovalTTL()))
		case domain.PlanApproved:
			expired = !now.Before(plan.WindowEnd) || now.After(plan.UpdatedAt.Add(s.timeouts.PlanTTL()))
		}
		if !expired {
			continue
		}
		_ = policy
		if err := s.expirePlanLocked(ctx, id, plan, now); err != nil {
			return err
		}
	}
	return nil
}

// expirePlanLocked transitions one plan to expired, revokes its tokens and audited.
func (s *Service) expirePlanLocked(ctx context.Context, id domain.PlanID, plan domain.WritePlan, now time.Time) error {
	if err := s.recordAudit(ctx, "system", "system", ActionPlanExpire, ObjectGatePlan, string(id), "window or TTL elapsed"); err != nil {
		return err
	}
	plan.State = domain.PlanExpired
	plan.UpdatedAt = now
	if err := s.repo.SavePlan(ctx, plan); err != nil {
		return fmt.Errorf("%w: save expired plan: %v", ErrStore, err)
	}
	s.plans[id] = plan
	for tokenID, token := range s.tokens {
		if token.PlanID != id || token.Revoked {
			continue
		}
		token.Revoked = true
		token.RevokedAt = now
		if err := s.repo.SaveToken(ctx, token); err != nil {
			return fmt.Errorf("%w: revoke token: %v", ErrStore, err)
		}
		s.tokens[tokenID] = token
	}
	s.emit(domain.GateEventPlanExpired, map[string]any{"plan_id": id, "state": plan.State})
	return nil
}

// Status returns the management status snapshot.
func (s *Service) Status(ctx context.Context) (Status, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.sweepLocked(ctx, true); err != nil {
		return Status{}, err
	}
	now := s.clock.Now().UTC()
	status := Status{}
	for _, plan := range s.plans {
		switch plan.State {
		case domain.PlanPending:
			status.Plans.Pending++
		case domain.PlanApproved:
			status.Plans.Approved++
		case domain.PlanExecuted:
			status.Plans.Executed++
		case domain.PlanRejected:
			status.Plans.Rejected++
		case domain.PlanExpired:
			status.Plans.Expired++
		case domain.PlanCancelled:
			status.Plans.Cancelled++
		}
	}
	dayStart := utcDayStart(now)
	for _, session := range s.sessions {
		if session.Usable(now) {
			status.Sessions.Active++
		}
		if !session.RevokedAt.IsZero() && !session.RevokedAt.Before(dayStart) {
			status.Sessions.RevokedToday++
		}
	}
	denies, err := s.repo.ListDenies(ctx, 0)
	if err != nil {
		return Status{}, fmt.Errorf("%w: list denies: %v", ErrStore, err)
	}
	cutoff := now.Add(-24 * time.Hour)
	for _, deny := range denies {
		if deny.At.After(cutoff) {
			status.Denies.Last24h++
		}
	}
	if len(denies) > 10 {
		status.Denies.Last = append([]domain.DeniedWriteAttempt(nil), denies[:10]...)
	} else {
		status.Denies.Last = append([]domain.DeniedWriteAttempt(nil), denies...)
	}
	ok, _, verr := s.repo.VerifyAudit(ctx)
	if verr != nil {
		return Status{}, fmt.Errorf("%w: verify audit: %v", ErrStore, verr)
	}
	status.Audit = AuditStats{ChainOK: ok, Entries: s.repo.AuditCount(), FirstSeq: s.repo.AuditFirstSeq()}
	return status, nil
}

// ListPlans returns every plan, newest request first.
func (s *Service) ListPlans(ctx context.Context) ([]domain.WritePlan, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.sweepLocked(ctx, false); err != nil {
		return nil, err
	}
	out := make([]domain.WritePlan, 0, len(s.plans))
	for _, plan := range s.plans {
		out = append(out, copyPlan(plan))
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].RequestedAt.Equal(out[j].RequestedAt) {
			return out[i].RequestedAt.After(out[j].RequestedAt)
		}
		return out[i].PlanID < out[j].PlanID
	})
	return out, nil
}

// GetPlan returns one plan.
func (s *Service) GetPlan(ctx context.Context, id domain.PlanID) (domain.WritePlan, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.sweepLocked(ctx, false); err != nil {
		return domain.WritePlan{}, false, err
	}
	plan, ok := s.plans[id]
	return copyPlan(plan), ok, nil
}

// ListSessions returns every write session, newest first.
func (s *Service) ListSessions(ctx context.Context) ([]domain.WriteSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	activeOnly := false
	_ = activeOnly
	out := make([]domain.WriteSession, 0, len(s.sessions))
	for _, session := range s.sessions {
		out = append(out, copySession(session))
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].SessionID < out[j].SessionID
	})
	return out, nil
}

// GetSession returns one session.
func (s *Service) GetSession(ctx context.Context, id domain.SessionID) (domain.WriteSession, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[id]
	return copySession(session), ok, nil
}

// ListDenies returns the denial evidence records (newest first).
func (s *Service) ListDenies(ctx context.Context, limit int) ([]domain.DeniedWriteAttempt, error) {
	denies, err := s.repo.ListDenies(ctx, limit)
	if err != nil {
		return nil, fmt.Errorf("%w: list denies: %v", ErrStore, err)
	}
	return denies, nil
}

// ListAudit returns the newest audit entries in ascending sequence order.
func (s *Service) ListAudit(ctx context.Context, limit int) ([]domain.AuditEntry, error) {
	entries, err := s.repo.ListAudit(ctx, limit)
	if err != nil {
		return nil, fmt.Errorf("%w: list audit: %v", ErrStore, err)
	}
	return entries, nil
}

// VerifyAudit re-reads and verifies the audit chain.
func (s *Service) VerifyAudit(ctx context.Context) (bool, uint64, error) {
	ok, badSeq, err := s.repo.VerifyAudit(ctx)
	if err != nil {
		return false, 0, fmt.Errorf("%w: verify audit: %v", ErrStore, err)
	}
	return ok, badSeq, nil
}

// AuditCount returns the number of persisted audit entries.
func (s *Service) AuditCount() int { return s.repo.AuditCount() }

// AuditFirstSeq returns the oldest persisted audit sequence number.
func (s *Service) AuditFirstSeq() uint64 { return s.repo.AuditFirstSeq() }

// utcDayStart returns the start of the UTC day of t.
func utcDayStart(t time.Time) time.Time {
	year, month, day := t.UTC().Date()
	return time.Date(year, month, day, 0, 0, 0, 0, time.UTC)
}

// copyPlan deep-copies a plan.
func copyPlan(plan domain.WritePlan) domain.WritePlan {
	out := plan
	out.Operations = append([]domain.WriteOperation(nil), plan.Operations...)
	out.Approvals = append([]domain.GateApproval(nil), plan.Approvals...)
	return out
}

// copySession deep-copies a session.
func copySession(session domain.WriteSession) domain.WriteSession { return session }

// copyToken deep-copies a token.
func copyToken(token domain.WriteToken) domain.WriteToken { return token }
