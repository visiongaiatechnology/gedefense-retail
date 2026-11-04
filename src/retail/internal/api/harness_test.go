package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/alert"
	"github.com/visiongaiatechnology/gedefense/retail/internal/config"
	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/policy"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
	"github.com/visiongaiatechnology/gedefense/retail/internal/state"
	"github.com/visiongaiatechnology/gedefense/retail/internal/store"
	"github.com/visiongaiatechnology/gedefense/retail/internal/vendorcatalog"
	"github.com/visiongaiatechnology/gedefense/retail/internal/version"
)

// defaultRemoteAddr makes handler tests look like a local browser client.
const defaultRemoteAddr = "127.0.0.1:54321"

const (
	adminToken    = "admin-token-0123456789abcdef"
	operatorToken = "operator-token-0123456789ab"
	viewerToken   = "viewer-token-0123456789abcd"
)

var baseTime = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

// fakeClock is a deterministic ports.Clock for the API tests.
type fakeClock struct {
	now time.Time
}

func (c *fakeClock) Now() time.Time { return c.now }

func tokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func testUsers() []config.User {
	return []config.User{
		{UserID: "admin", Name: "Admin", Role: config.RoleAdmin, TokenSHA256: tokenHash(adminToken)},
		{UserID: "operator-1", Name: "Operator", Role: config.RoleOperator, TokenSHA256: tokenHash(operatorToken)},
		{UserID: "viewer-1", Name: "Viewer", Role: config.RoleViewer, TokenSHA256: tokenHash(viewerToken)},
	}
}

func testSite() domain.Site {
	return domain.Site{
		SiteID: "filiale-001",
		Name:   "Markt Nord",
		Status: domain.SiteOnline,
		Zones: []domain.Zone{
			{ZoneID: "zone-ot", SiteID: "filiale-001", Name: "OT", Kind: domain.ZoneOTProcess, Critical: true},
		},
	}
}

type apiTestOptions struct {
	simulation bool
	static     fs.FS
	// hubLimit overrides the SSE subscriber limit (0 = default).
	hubLimit int
	// auditWrapper wraps the real audit store for the API dependency, so tests can
	// count or slow down verification calls.
	auditWrapper func(*store.AuditLog) ports.AuditStore
	security     *WhitelistConfig
	setup        bool
	configPath   string
	// vendorCatalog is the optional OT vendor catalog served by the monitoring
	// endpoints (nil = disabled catalog).
	vendorCatalog *vendorcatalog.Catalog
}

// apiHarness bundles a fully wired API server with real stores.
type apiHarness struct {
	server   *Server
	handler  http.Handler
	registry *state.Registry
	engine   *alert.Engine
	manager  *policy.Manager
	events   *store.EventLog
	alerts   *store.AlertStore
	audit    *store.AuditLog
	clock    *fakeClock
	dir      string
}

func newAPIHarness(t *testing.T, opts apiTestOptions) *apiHarness {
	t.Helper()
	dir := t.TempDir()
	clock := &fakeClock{now: baseTime}

	eventLog, err := store.OpenEventLog(store.Options{Dir: dir, Clock: clock})
	if err != nil {
		t.Fatalf("OpenEventLog: %v", err)
	}
	t.Cleanup(func() {
		if cerr := eventLog.Close(); cerr != nil {
			t.Errorf("EventLog.Close: %v", cerr)
		}
	})
	alertStore, err := store.OpenAlertStore(store.Options{Dir: dir, Clock: clock})
	if err != nil {
		t.Fatalf("OpenAlertStore: %v", err)
	}
	t.Cleanup(func() {
		if cerr := alertStore.Close(); cerr != nil {
			t.Errorf("AlertStore.Close: %v", cerr)
		}
	})
	auditLog, err := store.OpenAuditLog(store.Options{Dir: dir, Clock: clock})
	if err != nil {
		t.Fatalf("OpenAuditLog: %v", err)
	}
	t.Cleanup(func() {
		if cerr := auditLog.Close(); cerr != nil {
			t.Errorf("AuditLog.Close: %v", cerr)
		}
	})
	registry := state.NewRegistry([]domain.Site{testSite()}, clock)
	manager, err := policy.OpenManager(policy.Options{
		Dir:   dir + "/policy",
		Site:  "filiale-001",
		Clock: clock,
		Audit: auditLog,
	})
	if err != nil {
		t.Fatalf("OpenManager: %v", err)
	}
	hub := NewHub()
	if opts.hubLimit > 0 {
		hub = NewHubWithLimit(opts.hubLimit)
	}
	engine := alert.NewEngine(alert.Options{
		Store:   alertStore,
		Clock:   clock,
		Audit:   auditLog,
		Publish: hub.Publish,
	})
	auditDep := ports.AuditStore(auditLog)
	if opts.auditWrapper != nil {
		auditDep = opts.auditWrapper(auditLog)
	}
	staticFS := opts.static
	if staticFS == nil {
		staticFS = fstest.MapFS{
			"index.html":      &fstest.MapFile{Data: []byte("<!doctype html><title>GeDefense</title>")},
			"css/app.css":     &fstest.MapFile{Data: []byte("body{color:#fff}")},
			"js/app.js":       &fstest.MapFile{Data: []byte("export const ready = true;")},
			"assets/logo.png": &fstest.MapFile{Data: []byte{0x89, 'P', 'N', 'G'}},
			"secret.go":       &fstest.MapFile{Data: []byte("package main")},
		}
	}
	server, err := New(Deps{
		Version: version.Current(),
		Sites:   registry,
		Alerts:  engine,
		Policy:  manager,
		Events:  eventLog,
		Audit:   auditDep,
		Collectors: func() []ports.CollectorHealth {
			return []ports.CollectorHealth{
				{AdapterID: "modbus.pool1", State: "running", Events: 100},
				{AdapterID: "mqtt.cold1", State: "failed", Errors: 2},
			}
		},
		Stream:            hub,
		Static:            staticFS,
		Users:             testUsers(),
		SimulationEnabled: opts.simulation,
		Security:          securityDeps(opts.security),
		Setup:             buildSetupManager(t, opts, auditDep, registry, clock),
		VendorCatalog:     opts.vendorCatalog,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return &apiHarness{
		server:   server,
		handler:  server.Handler(),
		registry: registry,
		engine:   engine,
		manager:  manager,
		events:   eventLog,
		alerts:   alertStore,
		audit:    auditLog,
		clock:    clock,
		dir:      dir,
	}
}

// serve executes an already built request against the handler.
func (h *apiHarness) serve(req *http.Request) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	h.handler.ServeHTTP(recorder, req)
	return recorder
}

// newJSONRequest builds a request with a raw JSON body.
func newJSONRequest(t *testing.T, method, target, body, token string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req
}

// do executes one request against the handler.
func (h *apiHarness) do(t *testing.T, method, target string, body any, token string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal request body: %v", err)
		}
		reader = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, target, reader)
	req.RemoteAddr = defaultRemoteAddr
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	recorder := httptest.NewRecorder()
	h.handler.ServeHTTP(recorder, req)
	return recorder
}

// doRemote executes a request with a forged peer address.
func (h *apiHarness) doRemote(t *testing.T, method, target string, body any, token, remoteAddr string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal request body: %v", err)
		}
		reader = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, target, reader)
	req.RemoteAddr = remoteAddr
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	recorder := httptest.NewRecorder()
	h.handler.ServeHTTP(recorder, req)
	return recorder
}

// decode decodes a JSON response body.
func decode[T any](t *testing.T, recorder *httptest.ResponseRecorder) T {
	t.Helper()
	var out T
	if err := json.Unmarshal(recorder.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response %q: %v", recorder.Body.String(), err)
	}
	return out
}

// seedAlert creates one alert through the real engine.
func (h *apiHarness) seedAlert(t *testing.T, id, dedup string, severity domain.Severity, title string) domain.Alert {
	t.Helper()
	alertValue := domain.Alert{
		AlertID:     domain.AlertID(id),
		SiteID:      "filiale-001",
		ZoneIDs:     []domain.ZoneID{"zone-ot"},
		AssetIDs:    []domain.AssetID{"asset-1"},
		SensorIDs:   []domain.SensorID{"sensor-1"},
		Category:    domain.CategoryThermal,
		Severity:    severity,
		Confidence:  0.8,
		Title:       title,
		Summary:     "Zone 1 exceeded the configured maximum for 5 minutes.",
		RuleID:      domain.RuleID("retail.thermal.limit"),
		RuleVersion: "1",
		FirstSeenAt: baseTime,
		LastSeenAt:  baseTime,
		Status:      domain.AlertOpen,
		DedupKey:    dedup,
		Evidence: []domain.Evidence{{
			Kind: "event", RefID: "evt-1", Description: "limit crossed",
			At: baseTime, Source: "detect", Confidence: 0.9,
		}},
	}
	if err := h.engine.Observe(context.Background(), []domain.Alert{alertValue}); err != nil {
		t.Fatalf("seed alert: %v", err)
	}
	stored, ok, err := h.engine.Get(context.Background(), alertValue.AlertID)
	if err != nil || !ok {
		t.Fatalf("seeded alert missing: ok=%v err=%v", ok, err)
	}
	return stored
}

// seedEvent appends one event to the store and the registry.
func (h *apiHarness) seedEvent(t *testing.T, event domain.Event) {
	t.Helper()
	ctx := context.Background()
	if err := h.events.Append(ctx, event); err != nil {
		t.Fatalf("append event: %v", err)
	}
	if err := h.registry.Apply(ctx, event); err != nil {
		t.Fatalf("apply event: %v", err)
	}
}

// telemetryEvent builds a valid telemetry event.
func telemetryEvent(id string, at time.Time, sensor domain.SensorID, value float64) domain.Event {
	return domain.Event{
		EventID:    domain.EventID(id),
		Kind:       domain.EventTelemetry,
		SiteID:     "filiale-001",
		ZoneID:     "zone-ot",
		AssetID:    "asset-1",
		SensorID:   sensor,
		ObservedAt: at,
		ReceivedAt: at,
		Source:     "modbus.pool1",
		Collection: "read_only_poll",
		Protocol:   "modbus_tcp",
		Confidence: 0.9,
		Measurement: &domain.Measurement{
			Value: value, Unit: domain.UnitCelsius, Quality: domain.QualityGood,
			Metric: "air_temperature", ObservedAt: at,
		},
	}
}

// securityDeps resolves the optional whitelist test policy.
func securityDeps(cfg *WhitelistConfig) WhitelistConfig {
	if cfg == nil {
		return WhitelistConfig{}
	}
	return *cfg
}

// buildSetupManager builds a wizard manager when the test asks for one.
func buildSetupManager(t *testing.T, opts apiTestOptions, audit ports.AuditStore, sites *state.Registry, clock ports.Clock) *SetupManager {
	t.Helper()
	if !opts.setup {
		return nil
	}
	siteList := sites.Sites()
	base := config.Config{
		Listen: "127.0.0.1:8080", DataDir: t.TempDir(), LogLevel: "info",
		Site: siteList[0], Users: []config.User{}, Collectors: []config.AdapterConfig{},
	}
	path := opts.configPath
	if path == "" {
		path = filepath.Join(t.TempDir(), "retail.json")
		if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
			t.Fatalf("seed config: %v", err)
		}
	}
	return NewSetupManager(SetupOptions{ConfigPath: path, Base: base, Audit: audit, ListenHint: "127.0.0.1:8080", Clock: clock})
}
