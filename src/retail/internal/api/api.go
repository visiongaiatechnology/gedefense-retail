// Package api implements the HTTP v1 interface of GeDefense Retail.
//
// The server is a plain http.Handler so it can be exercised with httptest. It
// enforces the full contract: bearer authentication with constant-time token
// comparison, role based access control, per-token rate limiting, a hard body
// limit, strict JSON decoding, standard security headers including a strict CSP,
// opaque error responses, an SSE hub with bounded per-client buffering, static
// UI delivery from an fs.FS and the loopback-only simulator ingest path.
//
// Bounded resources: the SSE hub accepts at most 8 concurrent streams (further
// connections get 429 + Retry-After), every stream write is armed with its own
// 10 s deadline so a non-reading client cannot pin a goroutine, and the audit
// chain verification behind /health and /audit is cached for 30 s and reported
// with its checked-at timestamp. The audit log is append-only, so a cached "ok"
// can miss an out-of-band tamper for at most that window - never a new append.
package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/alert"
	"github.com/visiongaiatechnology/gedefense/retail/internal/config"
	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/i18n"
	"github.com/visiongaiatechnology/gedefense/retail/internal/policy"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
	"github.com/visiongaiatechnology/gedefense/retail/internal/state"
	"github.com/visiongaiatechnology/gedefense/retail/internal/version"
)

// Limits and defaults of the HTTP contract.
const (
	apiPrefix = "/api/v1"

	defaultListLimit = 50
	maxListLimit     = 200

	maxBodyBytes     = 256 << 10
	ratePerMinute    = 120
	rateBurst        = 40
	maxTokenLength   = 512
	maxRequestIDLen  = 64
	minRequestIDLen  = 8
	maxStaticBytes   = 16 << 20
	maxQueryTextLen  = 64
	maxColdChainSpan = 7 * 24 * time.Hour
	maxSeriesPoints  = 600

	// Window sizes of the derived read models.
	maxEventTimeline    = 500
	maxIntegrityEvents  = 1000
	maxIntegrityChanges = 100
	maxIncidentEvents   = 200
)

// Deps is the injected world of the HTTP layer. All lookups are served from
// these components; the API never reaches into global state.
type Deps struct {
	Version           version.Info
	Sites             *state.Registry
	Alerts            *alert.Engine
	Policy            *policy.Manager
	Events            ports.EventStore
	Audit             ports.AuditStore
	Collectors        func() []ports.CollectorHealth
	Stream            *Hub
	Static            fs.FS
	Users             []config.User
	SimulationEnabled bool
	// Ingest is the optional full pipeline entry used by the simulator ingest
	// path (validate -> store -> state -> detection -> alerting). When nil, the
	// API appends to the event store and the registry directly.
	Ingest func(ctx context.Context, events []domain.Event) error
	// Security is the resolved dashboard whitelist policy.
	Security WhitelistConfig
	// Setup is the first-run wizard manager (nil disables the setup API).
	Setup *SetupManager
	// DefaultLanguage is the operator-configured server language
	// (setup.language). Empty, invalid or unsupported values fall back to
	// English; the request header can always override it per request.
	DefaultLanguage string
}

// StreamTimings bounds one SSE connection.
type StreamTimings struct {
	Heartbeat   time.Duration
	Health      time.Duration
	MaxDuration time.Duration
	// WriteTimeout bounds one individual stream write. A client that stops
	// reading hits this deadline, so the stream ends and its goroutine plus file
	// descriptor are released even though the connection-level write timeout is
	// disabled for SSE.
	WriteTimeout time.Duration
}

func defaultStreamTimings() StreamTimings {
	return StreamTimings{
		Heartbeat:    15 * time.Second,
		Health:       30 * time.Second,
		MaxDuration:  30 * time.Minute,
		WriteTimeout: 10 * time.Second,
	}
}

// Server is the HTTP front end.
type Server struct {
	deps       Deps
	users      []userRecord
	limiter    *rateLimiter
	hub        *Hub
	started    time.Time
	stream     StreamTimings
	auditChain *auditVerifier
	filter     *ipFilter
	setup      *SetupManager
	// setupLimiter is the dedicated wizard rate-limit bucket (F-SW-06, 30/min/IP).
	setupLimiter *rateLimiter
	// defaultLanguage is the fallback language when a request carries no
	// explicit language (mutable only through Deps/SetDefaultLanguage).
	defaultLanguage i18n.Language
	logger          *slog.Logger

	handler http.Handler
}

// New validates the dependencies and builds the HTTP handler.
func New(deps Deps) (*Server, error) {
	if err := validateDeps(deps); err != nil {
		return nil, err
	}
	users, err := buildUsers(deps.Users)
	if err != nil {
		return nil, err
	}
	if deps.Stream == nil {
		deps.Stream = NewHub()
	}
	filter, err := newIPFilter(deps.Security)
	if err != nil {
		return nil, err
	}
	server := &Server{
		deps:            deps,
		users:           users,
		limiter:         newRateLimiter(ratePerMinute, rateBurst),
		hub:             deps.Stream,
		started:         time.Now().UTC(),
		stream:          defaultStreamTimings(),
		auditChain:      newAuditVerifier(deps.Audit, defaultAuditVerifyTTL),
		filter:          filter,
		setup:           deps.Setup,
		setupLimiter:    newRateLimiter(30, 30),
		defaultLanguage: i18n.DefaultFrom(deps.DefaultLanguage),
		logger:          slog.Default(),
	}
	server.handler = server.buildHandler()
	return server, nil
}

// SetDefaultLanguage overrides the server default language (test/demo hook; the
// composition root normally passes Deps.DefaultLanguage from setup.language).
// It must be called before the server starts serving.
func (s *Server) SetDefaultLanguage(raw string) {
	s.defaultLanguage = i18n.DefaultFrom(raw)
}

// Handler returns the composed http.Handler (middleware included).
func (s *Server) Handler() http.Handler { return s.handler }

// Hub returns the SSE hub the composition root publishes into.
func (s *Server) Hub() *Hub { return s.hub }

// SetStreamTimings overrides the SSE heartbeat/health/lifetime/write deadline. It
// is a test/demo hook and must be called before the server starts serving.
func (s *Server) SetStreamTimings(t StreamTimings) {
	if t.Heartbeat <= 0 || t.Health <= 0 || t.MaxDuration <= 0 {
		return
	}
	if t.WriteTimeout <= 0 {
		t.WriteTimeout = defaultStreamTimings().WriteTimeout
	}
	s.stream = t
}

// validateDeps enforces the mandatory dependencies.
func validateDeps(deps Deps) error {
	switch {
	case deps.Sites == nil:
		return fmt.Errorf("api: options: state registry is required")
	case deps.Alerts == nil:
		return fmt.Errorf("api: options: alert engine is required")
	case deps.Policy == nil:
		return fmt.Errorf("api: options: policy manager is required")
	case deps.Events == nil:
		return fmt.Errorf("api: options: event store is required")
	case deps.Audit == nil:
		return fmt.Errorf("api: options: audit store is required")
	case len(deps.Users) == 0:
		return fmt.Errorf("api: options: at least one user is required")
	}
	return nil
}

// userRecord is one configured user with its decoded token digest.
type userRecord struct {
	user config.User
	hash [sha256.Size]byte
}

// buildUsers decodes the configured SHA-256 token digests.
func buildUsers(users []config.User) ([]userRecord, error) {
	out := make([]userRecord, 0, len(users))
	for _, user := range users {
		raw, err := hex.DecodeString(strings.ToLower(strings.TrimSpace(user.TokenSHA256)))
		if err != nil || len(raw) != sha256.Size {
			return nil, fmt.Errorf("api: options: user %q has an invalid token_sha256", user.UserID)
		}
		if !user.Role.Valid() {
			return nil, fmt.Errorf("api: options: user %q has an invalid role %q", user.UserID, user.Role)
		}
		var digest [sha256.Size]byte
		copy(digest[:], raw)
		out = append(out, userRecord{user: user, hash: digest})
	}
	return out, nil
}
