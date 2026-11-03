package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/config"
	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
)

// Errors of the setup manager.
var (
	// ErrSetupIncomplete reports a complete call without admin or whitelist.
	ErrSetupIncomplete = errors.New("setup: admin and whitelist are required")
	// ErrSetupDisabled reports a setup call after completion.
	ErrSetupDisabled = errors.New("setup: already completed")
	// ErrSetupInvalid reports invalid wizard input.
	ErrSetupInvalid = errors.New("setup: invalid input")
	// ErrAdminExists reports a repeated admin creation (F-SW-03): the first
	// issued token stays valid and no second token is generated.
	ErrAdminExists = errors.New("setup: admin already configured")
	// ErrSetupAudit reports a failed audit write; the config is not modified
	// (F-SW-07: audit before effect, fail-closed).
	ErrSetupAudit = errors.New("setup: audit write failed")
)

// SetupOptions configures the first-run manager.
type SetupOptions struct {
	ConfigPath string
	Base       config.Config
	Audit      ports.AuditStore
	ListenHint string
	Clock      ports.Clock
}

// SetupManager drives the first-run wizard and persists the completed config.
type SetupManager struct {
	mu          sync.Mutex
	opts        SetupOptions
	clock       ports.Clock
	language    string
	site        *domain.Site
	cidrs       []string
	admin       *config.User
	adminName   string
	adapters    []string
	completed   bool
	completedAt time.Time

	// Setup session (F-SW-01/F-SW-06): only the SHA-256 of the plaintext token is
	// kept in memory; every state call rotates the session.
	sessionHash   string
	sessionExpiry time.Time
	sessionTTL    time.Duration
}

// NewSetupManager builds the wizard state from the current configuration.
func NewSetupManager(opts SetupOptions) *SetupManager {
	clock := opts.Clock
	if clock == nil {
		clock = realClock{}
	}
	manager := &SetupManager{opts: opts, clock: clock, language: opts.Base.SetupLanguage()}
	if opts.Base.Site.SiteID != "" {
		site := opts.Base.Site
		manager.site = &site
	}
	security := opts.Base.EffectiveSecurity()
	manager.cidrs = append([]string(nil), security.DashboardWhitelistCIDRs...)
	manager.completed = opts.Base.SetupCompleted()
	manager.sessionTTL = time.Duration(security.SetupTokenTTLS) * time.Second
	if manager.sessionTTL < time.Minute {
		manager.sessionTTL = time.Hour
	}
	if manager.sessionTTL > 24*time.Hour {
		manager.sessionTTL = 24 * time.Hour
	}
	return manager
}

// IssueSession creates a fresh setup session token (F-SW-01): crypto/rand 32
// bytes hex, only the SHA-256 digest is retained, TTL from
// security.setup_token_ttl_s. A new call invalidates the previous session.
func (m *SetupManager) IssueSession(now time.Time) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("setup: session entropy: %w", err)
	}
	token := hex.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))
	m.mu.Lock()
	m.sessionHash = hex.EncodeToString(sum[:])
	m.sessionExpiry = now.UTC().Add(m.sessionTTL)
	m.mu.Unlock()
	return token, nil
}

// VerifySession validates the setup session token constant-time and checks its
// TTL. Missing, rotated, expired and malformed tokens all return false.
func (m *SetupManager) VerifySession(token string, now time.Time) bool {
	if token == "" || len(token) != 64 {
		return false
	}
	sum := sha256.Sum256([]byte(token))
	digest := hex.EncodeToString(sum[:])
	m.mu.Lock()
	expected := m.sessionHash
	expiry := m.sessionExpiry
	m.mu.Unlock()
	if expected == "" || now.UTC().After(expiry) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(digest)) == 1
}

// BindHint returns the actual loopback setup URL (F-SW-08), derived from the
// listener hint. Non-loopback or wildcard hints are mapped to 127.0.0.1 so the
// operator is never pointed at a routable interface during first run.
func (m *SetupManager) BindHint() string {
	host, port, err := net.SplitHostPort(strings.TrimSpace(m.opts.ListenHint))
	if err != nil {
		return "http://127.0.0.1:8080/setup"
	}
	addr, parseErr := netip.ParseAddr(host)
	if parseErr != nil || addr.IsUnspecified() || !addr.IsLoopback() {
		host = "127.0.0.1"
	} else if addr.Is6() {
		host = "[" + addr.String() + "]"
	}
	return "http://" + host + ":" + port + "/setup"
}

// ListenPort returns the listener port used for Host/Origin binding.
func (m *SetupManager) ListenPort() string {
	_, port, err := net.SplitHostPort(strings.TrimSpace(m.opts.ListenHint))
	if err != nil {
		return "8080"
	}
	return port
}

// SessionTTL exposes the resolved setup session TTL (tests/diagnostics).
func (m *SetupManager) SessionTTL() time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sessionTTL
}

// Now returns the manager clock time (session TTL checks for the handlers).
func (m *SetupManager) Now() time.Time { return m.clock.Now().UTC() }

type realClock struct{}

func (realClock) Now() time.Time { return time.Now().UTC() }

// Completed reports whether the wizard already finished.
func (m *SetupManager) Completed() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.completed
}

// state is the GET /setup/state payload (no secrets, no hashes).
type setupState struct {
	Step            string       `json:"step"`
	Language        string       `json:"language"`
	Languages       []string     `json:"languages"`
	Site            *domain.Site `json:"site,omitempty"`
	Whitelist       []string     `json:"whitelist"`
	AdminConfigured bool         `json:"admin_configured"`
	Collectors      []string     `json:"collectors"`
	Completed       bool         `json:"completed"`
	RemoteIP        string       `json:"remote_ip,omitempty"`
	ListenHint      string       `json:"bind_hint,omitempty"`
	// SetupSession is the plaintext session token for the POST steps (F-SW-01).
	// It is returned only by the loopback GET /setup/state call.
	SetupSession string `json:"setup_session,omitempty"`
}

func (m *SetupManager) state(remoteIP string) setupState {
	m.mu.Lock()
	defer m.mu.Unlock()
	state := setupState{
		Language: m.language, Languages: config.SetupLanguages,
		Whitelist:       append([]string(nil), m.cidrs...),
		AdminConfigured: m.admin != nil,
		Collectors:      append([]string(nil), m.adapters...),
		Completed:       m.completed, RemoteIP: remoteIP, ListenHint: m.opts.ListenHint,
	}
	state.Step = "language"
	if state.Language != "" {
		state.Step = "site"
	}
	if m.site != nil && m.site.SiteID != "" {
		state.Step = "whitelist"
	}
	if len(state.Whitelist) > 0 {
		state.Step = "admin"
	}
	if state.AdminConfigured {
		state.Step = "collectors"
	}
	if len(state.Collectors) > 0 {
		state.Step = "complete"
	}
	if state.Completed {
		state.Step = "done"
	}
	if m.site != nil {
		site := *m.site
		state.Site = &site
	}
	return state
}

// audit records a setup step without any secret material.
func (m *SetupManager) audit(ctx context.Context, step, reason string) error {
	if m.opts.Audit == nil {
		return nil
	}
	_, err := m.opts.Audit.Append(ctx, domain.AuditEntry{
		At: m.clock.Now().UTC(), Actor: "setup", Role: "setup",
		Action: "setup." + step, ObjectType: "setup", ObjectID: "first-run", Reason: reason,
	})
	if err != nil {
		return fmt.Errorf("%w: audit: %v", ErrSetupInvalid, err)
	}
	return nil
}

// SetLanguage validates and stores the wizard language.
func (m *SetupManager) SetLanguage(ctx context.Context, language string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.completed {
		return ErrSetupDisabled
	}
	if !containsLang(config.SetupLanguages, language) {
		return fmt.Errorf("%w: unsupported language", ErrSetupInvalid)
	}
	m.language = language
	return m.audit(ctx, "language", "language="+language)
}

// SetSite validates and stores the store site.
func (m *SetupManager) SetSite(ctx context.Context, site domain.Site) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.completed {
		return ErrSetupDisabled
	}
	if site.Status == "" {
		site.Status = domain.SiteUnknown
	}
	if err := site.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrSetupInvalid, err)
	}
	m.site = &site
	return m.audit(ctx, "site", "site_id="+string(site.SiteID))
}

// SetWhitelist validates and stores the dashboard CIDRs; loopback is added
// automatically for local administration.
func (m *SetupManager) SetWhitelist(ctx context.Context, cidrs []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.completed {
		return ErrSetupDisabled
	}
	if len(cidrs) == 0 || len(cidrs) > 64 {
		return fmt.Errorf("%w: 1..64 CIDRs are required", ErrSetupInvalid)
	}
	normalized := make([]string, 0, len(cidrs)+2)
	seen := make(map[string]struct{}, len(cidrs)+2)
	add := func(raw string) error {
		prefix, err := parsePrefix(raw)
		if err != nil {
			return fmt.Errorf("%w: invalid CIDR %q", ErrSetupInvalid, raw)
		}
		text := prefix.String()
		if _, dup := seen[text]; dup {
			return nil
		}
		seen[text] = struct{}{}
		normalized = append(normalized, text)
		return nil
	}
	for _, raw := range cidrs {
		if err := add(raw); err != nil {
			return err
		}
	}
	if err := add("127.0.0.1/32"); err != nil {
		return err
	}
	if err := add("::1/128"); err != nil {
		return err
	}
	m.cidrs = normalized
	return m.audit(ctx, "whitelist", fmt.Sprintf("cidrs=%d", len(normalized)))
}

// SetAdminToken creates the admin identity. The plaintext token is returned
// exactly once; only its SHA-256 hash enters the config and the audit never sees it.
func (m *SetupManager) SetAdmin(ctx context.Context, userID, name string) (token string, tokenSHA256 string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.completed {
		return "", "", ErrSetupDisabled
	}
	id := domain.UserID(strings.TrimSpace(userID))
	if err := id.Validate(); err != nil {
		return "", "", fmt.Errorf("%w: invalid user id", ErrSetupInvalid)
	}
	// F-SW-03: repeated admin creation must not rotate the token or invalidate the
	// already issued credential. Only the first call returns a plaintext token.
	if m.admin != nil {
		_ = m.audit(ctx, "admin_exists", "duplicate_request_ignored")
		return "", "", ErrAdminExists
	}
	if strings.TrimSpace(name) == "" {
		name = string(id)
	}
	raw := make([]byte, 32)
	if _, rerr := rand.Read(raw); rerr != nil {
		return "", "", fmt.Errorf("setup: generate token: %w", rerr)
	}
	plain := hex.EncodeToString(raw)
	sum := sha256.Sum256([]byte(plain))
	hash := hex.EncodeToString(sum[:])
	m.admin = &config.User{UserID: id, Name: name, Role: config.RoleAdmin, TokenSHA256: hash}
	m.adminName = name
	if aerr := m.auditPlainTokenSafe(ctx, "admin", "user_id="+string(id)); aerr != nil {
		return "", "", aerr
	}
	return plain, hash, nil
}

// auditPlainTokenSafe records the admin step without the token.
func (m *SetupManager) auditPlainTokenSafe(ctx context.Context, step, reason string) error {
	return m.audit(ctx, step, reason)
}

// SetCollectors validates the optional adapter preselection.
func (m *SetupManager) SetCollectors(ctx context.Context, adapters []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.completed {
		return ErrSetupDisabled
	}
	known := map[string]struct{}{"modbus": {}, "mqtt": {}, "bacnet": {}, "snmp": {}, "pcap": {}}
	for _, adapter := range adapters {
		if _, ok := known[adapter]; !ok {
			return fmt.Errorf("%w: unknown adapter %q", ErrSetupInvalid, adapter)
		}
	}
	m.adapters = append([]string(nil), adapters...)
	return m.audit(ctx, "collectors", fmt.Sprintf("adapters=%d", len(adapters)))
}

// CompleteResult is the response of a completed wizard.
type CompleteResult struct {
	Completed       bool   `json:"completed"`
	RestartRequired bool   `json:"restart_required"`
	BindHint        string `json:"bind_hint,omitempty"`
}

// Complete validates the wizard, writes the configuration atomically (temp+rename,
// 0600) and disables the setup API.
func (m *SetupManager) Complete(ctx context.Context) (CompleteResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.completed {
		return CompleteResult{}, ErrSetupDisabled
	}
	if m.admin == nil || len(m.cidrs) == 0 {
		return CompleteResult{}, ErrSetupIncomplete
	}
	if m.site == nil || m.site.SiteID == "" {
		return CompleteResult{}, fmt.Errorf("%w: site is required", ErrSetupIncomplete)
	}
	now := m.clock.Now().UTC()
	update := m.opts.Base
	update.Site = *m.site
	update.Setup = &config.SetupState{Completed: true, CompletedAt: now.Format(time.RFC3339), Language: m.language}
	require := true
	update.Security = &config.SecurityConfig{
		RequireWhitelist: &require, DashboardWhitelistCIDRs: append([]string(nil), m.cidrs...),
		TrustProxyHeaders: m.opts.Base.EffectiveSecurity().TrustProxyHeaders,
		TrustedProxyCIDRs: append([]string(nil), m.opts.Base.EffectiveSecurity().TrustedProxyCIDRs...),
		SetupTokenTTLS:    m.opts.Base.EffectiveSecurity().SetupTokenTTLS,
	}
	users := make([]config.User, 0, len(m.opts.Base.Users)+1)
	replaced := false
	for _, user := range m.opts.Base.Users {
		if user.UserID == m.admin.UserID {
			users = append(users, *m.admin)
			replaced = true
			continue
		}
		users = append(users, user)
	}
	if !replaced {
		users = append(users, *m.admin)
	}
	update.Users = users
	update.Collectors = adapterConfigs(update.Collectors, m.adapters, m.site.SiteID)
	if err := update.Validate(); err != nil {
		return CompleteResult{}, fmt.Errorf("%w: %v", ErrSetupInvalid, err)
	}
	// F-SW-07: audit the completion BEFORE the configuration has any effect. If
	// the audit write fails, the request fails (500) and no file is modified.
	if err := m.audit(ctx, "complete", "restart_required"); err != nil {
		return CompleteResult{}, fmt.Errorf("%w: %v", ErrSetupAudit, err)
	}
	if err := writeConfigAtomic(m.opts.ConfigPath, update); err != nil {
		return CompleteResult{}, err
	}
	m.completed = true
	m.completedAt = now
	return CompleteResult{Completed: true, RestartRequired: true, BindHint: m.BindHint()}, nil
}

// adapterConfigs enables the selected adapters (existing entries keep their options).
func adapterConfigs(existing []config.AdapterConfig, selected []string, site domain.SiteID) []config.AdapterConfig {
	out := append([]config.AdapterConfig(nil), existing...)
	for _, adapter := range selected {
		found := false
		for i := range out {
			if strings.HasPrefix(out[i].AdapterID, adapter) {
				out[i].Enabled = true
				found = true
			}
		}
		if !found {
			out = append(out, config.AdapterConfig{AdapterID: adapter, Enabled: true})
		}
	}
	_ = site
	return out
}

// writeConfigAtomic writes the configuration through a 0600 temporary file and a
// rename in the same directory (crash-safe, no partial config).
func writeConfigAtomic(path string, cfg config.Config) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("setup: configuration path is empty")
	}
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("setup: marshal config: %w", err)
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".setup-*.json")
	if err != nil {
		return fmt.Errorf("setup: create temporary config: %w", err)
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if cerr := tmp.Chmod(0o600); cerr != nil {
		closeErr := tmp.Close()
		return fmt.Errorf("setup: chmod config: %v", errors.Join(cerr, closeErr))
	}
	if _, werr := tmp.Write(append(raw, '\n')); werr != nil {
		closeErr := tmp.Close()
		return fmt.Errorf("setup: write config: %v", errors.Join(werr, closeErr))
	}
	if serr := tmp.Sync(); serr != nil {
		closeErr := tmp.Close()
		return fmt.Errorf("setup: sync config: %v", errors.Join(serr, closeErr))
	}
	if cerr := tmp.Close(); cerr != nil {
		return fmt.Errorf("setup: close config: %w", cerr)
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("setup: replace config: %w", err)
	}
	return nil
}
