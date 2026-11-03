package gateapp

import (
	"context"
	"crypto/subtle"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/alert"
	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/api"
	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/approval"
	gateconfig "github.com/visiongaiatechnology/gedefense/retail/internal/gate/config"
	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/failsafe"
	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/identity"
	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/notify"
	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/store"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
)

// --- ports adapters ------------------------------------------------------

// systemClock is the production clock (UTC).
type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now().UTC() }

// policyHolder stores the active policy atomically (reload swaps it).
type policyHolder struct {
	ptr atomic.Pointer[gateconfig.Policy]
}

func newPolicyHolder(p gateconfig.Policy) *policyHolder {
	h := &policyHolder{}
	h.set(p)
	return h
}

func (h *policyHolder) set(p gateconfig.Policy) { h.ptr.Store(&p) }

func (h *policyHolder) get() gateconfig.Policy {
	p := h.ptr.Load()
	if p == nil {
		return gateconfig.Policy{}
	}
	return *p
}

func (h *policyHolder) notifyThreshold() domain.Severity {
	s := h.get().Notify.DenyMinSeverity
	if !s.Valid() {
		return domain.SeverityMedium
	}
	return s
}

// auditSink adapts store.Store to alert.AuditSink and tracks append health.
type auditSink struct {
	store   *store.Store
	failing atomic.Bool
}

func newAuditSink(st *store.Store) *auditSink { return &auditSink{store: st} }

func (a *auditSink) Append(ctx context.Context, entry domain.AuditEntry) error {
	if _, err := a.store.AppendAudit(ctx, entry); err != nil {
		a.failing.Store(true)
		return err
	}
	a.failing.Store(false)
	return nil
}

func (a *auditSink) state() failsafe.AuditState {
	if a.failing.Load() {
		return failsafe.AuditAppendFailing
	}
	return failsafe.AuditOK
}

// alertPublisher forwards gate alerts to the SSE hub.
type alertPublisher struct{ hub *api.Hub }

func (p alertPublisher) Publish(a alert.Alert) {
	p.hub.Publish(domain.GateEventKind("gate_alert"), a)
}

// escalatingNotifier delivers notifications and tracks high-severity ones for
// the 24/7 escalation chain. Delivery failures never block the gate core.
type escalatingNotifier struct {
	dispatcher *notify.Dispatcher
	escalator  *notify.Escalator
	clock      ports.Clock
}

func (n *escalatingNotifier) Notify(ctx context.Context, msg notify.Notification) error {
	err := n.dispatcher.Notify(ctx, msg)
	if msg.Severity.Rank() >= domain.SeverityHigh.Rank() {
		if _, _, terr := n.escalator.Track(ctx, msg); terr != nil {
			if err == nil {
				return terr
			}
		}
	}
	return err
}

// nopNotifier is used when no webhook is configured (log-only alpha).
type nopNotifier struct{}

func (nopNotifier) Notify(context.Context, notify.Notification) error { return nil }

// browserAuth implements httpproxy.Authenticator for the proxied supervisor UI.
type browserAuth struct {
	svc   *identity.Service
	clock ports.Clock
	ttl   time.Duration
	mu    sync.Mutex
	sess  map[string]browserSession
}

type browserSession struct {
	user    domain.GateUserID
	expires time.Time
}

func newBrowserAuth(svc *identity.Service, clock ports.Clock, ttl time.Duration) *browserAuth {
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	return &browserAuth{svc: svc, clock: clock, ttl: ttl, sess: map[string]browserSession{}}
}

func (b *browserAuth) Login(ctx context.Context, userID, password, totp string) (domain.GateUserID, string, error) {
	res, err := b.svc.Authenticate(ctx, identity.LoginRequest{UserID: userID, Password: password, TOTP: totp})
	if err != nil {
		return "", "", err
	}
	token := randomToken()
	b.mu.Lock()
	b.sess[token] = browserSession{user: res.User.UserID, expires: b.clock.Now().Add(b.ttl)}
	b.mu.Unlock()
	return res.User.UserID, token, nil
}

func (b *browserAuth) Authenticate(_ context.Context, token string) (domain.GateUserID, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	s, ok := b.sess[token]
	if !ok || b.clock.Now().After(s.expires) {
		delete(b.sess, token)
		return "", false
	}
	return s.user, true
}

func (b *browserAuth) Logout(_ context.Context, token string) error {
	b.mu.Lock()
	delete(b.sess, token)
	b.mu.Unlock()
	return nil
}

// constantTimeEqual is used for token comparisons (kept here so adapters do not
// import crypto/subtle ad hoc).
func constantTimeEqual(a, b string) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// randomToken returns an opaque 32-byte hex token for browser sessions.
func randomToken() string {
	return randomHex(32)
}

// alertingSessionLookup delegates session decisions to the approval service and
// routes every denial into the alert engine (audit + webhook + SSE).
type alertingSessionLookup struct {
	approval *approval.Service
	alerts   *alert.Engine
}

func (l *alertingSessionLookup) Lookup(targetID domain.TargetID, sourceIP string, now time.Time) (domain.WriteSession, bool) {
	return l.approval.Lookup(targetID, sourceIP, now)
}

func (l *alertingSessionLookup) ConsumeUse(sessionID domain.SessionID, now time.Time) bool {
	return l.approval.ConsumeUse(sessionID, now)
}

func (l *alertingSessionLookup) PlanFor(sessionID domain.SessionID) (domain.WritePlan, bool) {
	return l.approval.PlanFor(sessionID)
}

func (l *alertingSessionLookup) Deny(ctx context.Context, attempt domain.DeniedWriteAttempt) error {
	if err := l.approval.Deny(ctx, attempt); err != nil {
		return err
	}
	if l.alerts != nil {
		if _, aerr := l.alerts.OnDeniedWrite(ctx, attempt); aerr != nil {
			// Alerting failures must never turn a deny into an allow.
			return fmt.Errorf("deny recorded, alert failed: %w", aerr)
		}
	}
	return nil
}

func (l *alertingSessionLookup) Allowed(ctx context.Context, sessionID domain.SessionID, op domain.WriteOperation) error {
	return l.approval.Allowed(ctx, sessionID, op)
}
