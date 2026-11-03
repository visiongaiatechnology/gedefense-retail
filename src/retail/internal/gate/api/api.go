// Package api implements the Access Gate management API (/api/v1/gate).
//
// The gate is the only path to configuration writes; this API manages identities,
// plans, approvals, sessions, denials and the hash-chained audit trail. It never
// performs an OT write itself: the protocol proxies call approval.SessionLookup.
//
// Hardening mirrors the 0.1 monitoring API: bearer sessions, RBAC, strict JSON,
// 128 KiB body limit, per-token rate limiting (login per source address), request
// ids, security headers, bounded SSE (8 streams, 64-event buffers, write
// deadlines) and an audit-chain verification cache for the public health probe.
package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/approval"
	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/config"
	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/identity"
)

// Limits and defaults of the gate HTTP contract.
const (
	apiPrefix       = "/api/v1/gate"
	maxBodyBytes    = 128 << 10
	ratePerMinute   = 60
	rateBurst       = 20
	loginPerMinute  = 10
	loginBurst      = 5
	defaultList     = 50
	maxListLimit    = 200
	auditVerifyTTL  = 30 * time.Second
	apiSessionBytes = 32
)

// Info is the immutable product identity surfaced by health/status.
type Info struct {
	Product   string
	Version   string
	Commit    string
	BuildDate string
}

// Deps is the injected gate world.
type Deps struct {
	Info     Info
	Config   config.Config
	Identity *identity.Service
	Gate     *approval.Service
	Stream   *Hub
	// Targets reports the listener health of the protocol proxies.
	Targets func() []config.TargetStatus
	// Failsafe reports an active fail-safe and its reason.
	Failsafe func() (bool, string)
	// NotifyTest triggers a test notification (master_admin only).
	NotifyTest func(ctx context.Context) error
	// LoadPolicy validates and returns a new policy without activating it.
	LoadPolicy func() (config.Policy, error)
	// ActivatePolicy installs a validated policy version.
	ActivatePolicy func(policy config.Policy) error
	// Policy returns the currently active policy.
	Policy func() config.Policy
	// Escalations exposes the 24/7 notifier escalation state (optional).
	Escalations *EscalationHooks
}

// wallClock is the default ports.Clock replacement for API timestamps.
type wallClock struct{}

func (wallClock) Now() time.Time { return time.Now().UTC() }

// Server is the gate management HTTP front end.
type Server struct {
	deps         Deps
	sessions     *sessionStore
	limiter      *rateLimiter
	loginLimiter *rateLimiter
	hub          *Hub
	idem         *idempotencyCache
	audit        *auditVerifier
	started      time.Time
	stream       StreamTimings
	logger       *slog.Logger
	handler      http.Handler
}

// New validates the dependencies and builds the handler.
func New(deps Deps) (*Server, error) {
	if deps.Identity == nil || deps.Gate == nil || deps.Config.PolicyFile == "" {
		return nil, fmt.Errorf("gate api: identity, gate and configuration are required")
	}
	if deps.Policy == nil || deps.LoadPolicy == nil || deps.ActivatePolicy == nil {
		return nil, fmt.Errorf("gate api: policy callbacks are required")
	}
	if deps.Info.Product == "" {
		deps.Info.Product = "GeDefense Retail Access Gate"
	}
	if deps.Stream == nil {
		deps.Stream = NewHub()
	}
	server := &Server{
		deps:         deps,
		sessions:     newSessionStore(4096),
		limiter:      newRateLimiter(ratePerMinute, rateBurst),
		loginLimiter: newRateLimiter(loginPerMinute, loginBurst),
		hub:          deps.Stream,
		idem:         newIdempotencyCache(10 * time.Minute),
		audit:        newAuditVerifier(deps.Gate, auditVerifyTTL),
		started:      time.Now().UTC(),
		stream:       defaultStreamTimings(),
		logger:       slog.Default(),
	}
	server.handler = server.buildHandler()
	return server, nil
}

// Handler returns the composed HTTP handler.
func (s *Server) Handler() http.Handler { return s.handler }

// Hub returns the SSE hub the composition root may publish into.
func (s *Server) Hub() *Hub { return s.hub }

// PublishEvent fans a gate event (plan, deny, failsafe notice, bypass suspicion)
// out to the SSE stream. The composition root uses it for failsafe notices.
func (s *Server) PublishEvent(event domain.GateEvent) {
	if event.Kind == "" {
		return
	}
	payload := any(event)
	if len(event.Payload) > 0 {
		payload = json.RawMessage(event.Payload)
	}
	s.hub.Publish(event.Kind, payload)
}

// SetStreamTimings overrides the SSE timings (tests/demo, before serving).
func (s *Server) SetStreamTimings(t StreamTimings) {
	if t.Heartbeat <= 0 || t.Health <= 0 || t.MaxDuration <= 0 {
		return
	}
	if t.WriteTimeout <= 0 {
		t.WriteTimeout = defaultStreamTimings().WriteTimeout
	}
	s.stream = t
}

// SetAuditVerifyTTL overrides the audit verification cache TTL (tests/ops).
func (s *Server) SetAuditVerifyTTL(ttl time.Duration) { s.audit.setTTL(ttl) }

// now returns the current UTC time.
func (s *Server) now() time.Time { return time.Now().UTC() }

// targetStatus returns the proxy listener state.
func (s *Server) targetStatus() []config.TargetStatus {
	if s.deps.Targets == nil {
		return []config.TargetStatus{}
	}
	status := s.deps.Targets()
	if status == nil {
		return []config.TargetStatus{}
	}
	return status
}

// failsafeState returns the fail-safe snapshot.
func (s *Server) failsafeState() (bool, string) {
	if s.deps.Failsafe == nil {
		return false, ""
	}
	return s.deps.Failsafe()
}

// policy returns the active policy.
func (s *Server) policy() config.Policy { return s.deps.Policy() }

// tokenHash hashes an API session token for storage/lookup.
func tokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// newAPIToken creates a "gst_<64hex>" bearer token.
func newAPIToken() (string, error) {
	raw := make([]byte, apiSessionBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return "gst_" + hex.EncodeToString(raw), nil
}

// clientIP returns the transport peer address (forwarding headers are ignored).
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// userRoles renders the role list of a user.
func userRoles(user domain.GateUser) []domain.GateRole { return user.Roles }

// hasAnyRole reports whether the user carries one of the roles.
func hasAnyRole(user domain.GateUser, roles []domain.GateRole) bool {
	for _, role := range roles {
		if user.HasRole(role) {
			return true
		}
	}
	return false
}

// isVendorOnly reports whether the user has only vendor roles (own data only).
func isVendorOnly(user domain.GateUser) bool {
	for _, role := range user.Roles {
		switch role {
		case domain.GateRoleVendorRead, domain.GateRoleVendorWriteRequester:
		default:
			return false
		}
	}
	return len(user.Roles) > 0
}

// roleList renders a comma separated role list for audit records.
func roleList(user domain.GateUser) string {
	parts := make([]string, 0, len(user.Roles))
	for _, role := range user.Roles {
		parts = append(parts, string(role))
	}
	return strings.Join(parts, ",")
}
