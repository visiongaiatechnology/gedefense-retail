// Package app is the composition root of the GeDefense Retail gateway. It wires
// the storage layer, the in-memory registry, the passive collectors, the
// detection/correlation engines, the alert workflow, the HTTP API and the
// optional central forwarder into one fail-safe process.
//
// Design rules enforced here (not in the individual packages):
//   - a failing adapter, notifier or forwarder never stops the core pipeline;
//   - the HTTP server is shut down gracefully and always bounded in time;
//   - no code path in this package can write to an OT device (see internal/guard);
//   - the demo/simulation mode is only reachable with a loopback configuration.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/adapters/bacnet"
	"github.com/visiongaiatechnology/gedefense/retail/internal/adapters/httpui"
	"github.com/visiongaiatechnology/gedefense/retail/internal/adapters/modbus"
	"github.com/visiongaiatechnology/gedefense/retail/internal/adapters/mqtt"
	"github.com/visiongaiatechnology/gedefense/retail/internal/adapters/pcap"
	"github.com/visiongaiatechnology/gedefense/retail/internal/adapters/snmp"
	"github.com/visiongaiatechnology/gedefense/retail/internal/alert"
	"github.com/visiongaiatechnology/gedefense/retail/internal/api"
	"github.com/visiongaiatechnology/gedefense/retail/internal/collect"
	"github.com/visiongaiatechnology/gedefense/retail/internal/config"
	"github.com/visiongaiatechnology/gedefense/retail/internal/correlate"
	"github.com/visiongaiatechnology/gedefense/retail/internal/demo"
	"github.com/visiongaiatechnology/gedefense/retail/internal/detect"
	"github.com/visiongaiatechnology/gedefense/retail/internal/discovery"
	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/policy"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
	"github.com/visiongaiatechnology/gedefense/retail/internal/state"
	"github.com/visiongaiatechnology/gedefense/retail/internal/store"
	"github.com/visiongaiatechnology/gedefense/retail/internal/version"
	"github.com/visiongaiatechnology/gedefense/retail/internal/webui"
)

// Options controls optional runtime behaviour.
type Options struct {
	// Demo seeds the demo site, inventory and one synthetic attack scenario.
	// It requires a loopback simulation configuration (validated in Run).
	Demo bool
	// Logger receives structured logs. Nil uses a JSON logger on stderr.
	Logger *slog.Logger
	// ConfigPath is the retail.json path used by the setup wizard to persist the
	// completed configuration atomically.
	ConfigPath string
}

// gateway holds the long-lived components of one running instance.
type gateway struct {
	cfg     config.Config
	log     *slog.Logger
	clock   ports.Clock
	events  *store.EventLog
	alerts  *store.AlertStore
	audit   *store.AuditLog
	spool   *store.Spool
	policy  *policy.Manager
	reg     *state.Registry
	alertsE *alert.Engine
	detect  *detect.Engine
	corr    *correlate.Engine
	hub     *api.Hub
	pipe    *pipeline
	collect *collect.Registry
	api     *api.Server
}

// Run starts the gateway and blocks until ctx is cancelled. It returns the
// first fatal startup error; runtime errors are logged and contained.
func Run(ctx context.Context, cfg config.Config, opts Options) error {
	if ctx == nil {
		return errors.New("app: nil context")
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	if opts.Demo && !cfg.SimulationEnabled() {
		return errors.New("app: --demo requires simulation.enabled=true with a loopback listen address")
	}

	if opts.Demo {
		nowUTC := time.Now().UTC()
		cfg.Site = demo.Site(nowUTC)
		if cfg.Policy == nil || cfg.Policy.SiteID != cfg.Site.SiteID {
			p := demo.Policy(nowUTC)
			cfg.Policy = &p
		}
	}

	log := opts.Logger
	if log == nil {
		log = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}
	log = log.With("product", version.Product, "version", version.Version, "site", cfg.Site.SiteID)

	clock := systemClock{}
	listenAddr := cfg.EffectiveListen()
	if cfg.SetupMode() {
		if _, port, splitErr := net.SplitHostPort(listenAddr); splitErr == nil {
			listenAddr = net.JoinHostPort("127.0.0.1", port)
		}
	}
	g, err := newGateway(cfg, log, clock, opts.ConfigPath, listenAddr)
	if err != nil {
		return err
	}
	defer g.close()

	if opts.Demo {
		if err := g.seedDemo(ctx); err != nil {
			return fmt.Errorf("app: demo seed: %w", err)
		}
	}

	// HTTP server with bounded timeouts. WriteTimeout is intentionally zero:
	// the SSE endpoint is a long-lived stream and would otherwise be cut off.
	// Every streaming response bounds itself by a 30 minute stream limit.
	handler := g.api.Handler()
	httpServer := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      0,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("app: listen %q: %w", listenAddr, err)
	}
	log.Info("gateway starting", "listen", ln.Addr().String(), "demo", opts.Demo, "collectors", len(cfg.Collectors))

	// Adapter startup is transactional: a configuration error aborts startup
	// before any goroutine is launched.
	adapterCfgs := make([]collect.AdapterConfig, 0, len(cfg.Collectors))
	for _, a := range cfg.Collectors {
		if !a.Enabled {
			continue
		}
		adapterCfgs = append(adapterCfgs, collect.AdapterConfig{
			AdapterID: a.AdapterID,
			SiteID:    cfg.Site.SiteID,
			ZoneID:    a.ZoneID,
			Options:   a.Options,
			Clock:     clock,
		})
	}
	if err := g.collect.Start(ctx, adapterCfgs, g.pipe); err != nil {
		_ = ln.Close()
		return fmt.Errorf("app: start collectors: %w", err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if serveErr := httpServer.Serve(ln); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			log.Error("http server stopped", "error", serveErr.Error())
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		g.runLoops(ctx)
	}()

	<-ctx.Done()
	log.Info("shutdown requested")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Warn("http shutdown incomplete", "error", err.Error())
		_ = httpServer.Close()
	}
	wg.Wait()
	log.Info("gateway stopped")
	return nil
}

// newGateway opens storage, the registry and the detection/alert/API stack.
func newGateway(cfg config.Config, log *slog.Logger, clock ports.Clock, configPath, listenAddr string) (*gateway, error) {
	dataDir := cfg.EffectiveDataDir()
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("app: create data dir: %w", err)
	}

	auditLog, err := store.OpenAuditLog(store.Options{Dir: dataDir, Clock: clock})
	if err != nil {
		return nil, fmt.Errorf("app: open audit log: %w", err)
	}

	site := cfg.Site
	var initial *domain.Policy
	if cfg.Policy != nil {
		initial = cfg.Policy
	}
	policyMgr, err := policy.OpenManager(policy.Options{
		Dir:     filepath.Join(dataDir, "policy"),
		Site:    site.SiteID,
		Clock:   clock,
		Audit:   auditLog,
		Initial: initial,
	})
	if err != nil {
		_ = auditLog.Close()
		return nil, fmt.Errorf("app: open policy: %w", err)
	}
	activePolicy := policyMgr.Current()

	events, err := store.OpenEventLog(store.Options{
		Dir:           dataDir,
		MaxMB:         activePolicy.Retention.MaxEventMB,
		RetentionDays: activePolicy.Retention.EventDays,
		Clock:         clock,
	})
	if err != nil {
		_ = auditLog.Close()
		return nil, fmt.Errorf("app: open event log: %w", err)
	}

	alertStore, err := store.OpenAlertStore(store.Options{
		Dir:           dataDir,
		RetentionDays: activePolicy.Retention.AlertDays,
		Clock:         clock,
	})
	if err != nil {
		_ = events.Close()
		_ = auditLog.Close()
		return nil, fmt.Errorf("app: open alert store: %w", err)
	}

	hub := api.NewHub()
	alertEngine := alert.NewEngine(alert.Options{
		Store:   alertStore,
		Clock:   clock,
		Audit:   auditLog,
		Publish: hub.Publish,
		MinNotify: func() domain.Severity {
			return policyMgr.Current().Alerting.MinNotifySeverity
		},
		Notifier: newLogNotifier(log),
	})

	reg := state.NewRegistry([]domain.Site{site}, clock)

	var spool *store.Spool
	var spoolPort ports.Spool
	if cfg.Central != nil {
		fwd, ferr := newHTTPForwarder(cfg.Central, site.SiteID)
		if ferr != nil {
			_ = alertStore.Close()
			_ = events.Close()
			_ = auditLog.Close()
			return nil, fmt.Errorf("app: central forwarder: %w", ferr)
		}
		spool, err = store.OpenSpool(store.Options{
			Dir:       dataDir,
			MaxMB:     activePolicy.Retention.MaxSpoolMB,
			Clock:     clock,
			Forwarder: fwd,
		})
		if err != nil {
			_ = alertStore.Close()
			_ = events.Close()
			_ = auditLog.Close()
			return nil, fmt.Errorf("app: open spool: %w", err)
		}
	}

	// Assign the spool only when it exists. A typed nil (*store.Spool)(nil)
	// stored in the ports.Spool interface is not nil and would panic on use.
	if spool != nil {
		spoolPort = spool
	}

	dw := detectionWorld{Registry: reg, policy: policyMgr}
	det := detect.NewEngine(dw, clock)
	corr := correlate.NewEngine(reg, clock)

	disc := discovery.New(discovery.Options{
		Clock:       clock,
		VendorsPath: otCatalogPath(),
		ZoneID:      "",
	})

	pipe := newPipeline(pipelineDeps{
		Log:       log,
		Clock:     clock,
		Events:    events,
		Registry:  reg,
		Policy:    policyMgr,
		Detect:    det,
		Correlate: corr,
		Alerts:    alertEngine,
		Discovery: disc,
		Spool:     spoolPort,
		Hub:       hub,
		SiteID:    site.SiteID,
	})

	collectReg := collect.NewRegistry(clock)
	for _, f := range []collect.Factory{
		{AdapterID: "modbus", New: modbus.New},
		{AdapterID: "mqtt", New: mqtt.New},
		{AdapterID: "bacnet", New: bacnet.New},
		{AdapterID: "snmp", New: snmp.New},
		{AdapterID: "pcap", New: pcap.New},
		{AdapterID: "httpui", New: httpui.New},
	} {
		if err := collectReg.Register(f); err != nil {
			_ = alertStore.Close()
			_ = events.Close()
			_ = auditLog.Close()
			return nil, fmt.Errorf("app: register adapter %q: %w", f.AdapterID, err)
		}
	}

	security := cfg.EffectiveSecurity()
	requireWhitelist := security.RequireWhitelist != nil && *security.RequireWhitelist
	setupManager := api.NewSetupManager(api.SetupOptions{
		ConfigPath: configPath, Base: cfg, Audit: auditLog, ListenHint: listenAddr,
	})
	apiServer, err := api.New(api.Deps{
		Version:           version.Current(),
		Sites:             reg,
		Alerts:            alertEngine,
		Policy:            policyMgr,
		Events:            events,
		Audit:             auditLog,
		Collectors:        collectReg.Health,
		Stream:            hub,
		Static:            webui.FS(),
		Users:             cfg.Users,
		SimulationEnabled: cfg.SimulationEnabled(),
		Ingest:            pipe.ProcessBatch,
		Security: api.WhitelistConfig{
			RequireWhitelist:  requireWhitelist,
			CIDRs:             security.DashboardWhitelistCIDRs,
			TrustProxyHeaders: security.TrustProxyHeaders,
			TrustedProxyCIDRs: security.TrustedProxyCIDRs,
			SetupMode:         cfg.SetupMode(),
		},
		Setup:           setupManager,
		DefaultLanguage: cfg.SetupLanguage(),
	})
	if err != nil {
		_ = alertStore.Close()
		_ = events.Close()
		_ = auditLog.Close()
		return nil, fmt.Errorf("app: API: %w", err)
	}

	return &gateway{
		cfg:     cfg,
		log:     log,
		clock:   clock,
		events:  events,
		alerts:  alertStore,
		audit:   auditLog,
		spool:   spool,
		policy:  policyMgr,
		reg:     reg,
		alertsE: alertEngine,
		detect:  det,
		corr:    corr,
		hub:     hub,
		pipe:    pipe,
		collect: collectReg,
		api:     apiServer,
	}, nil
}

// close releases storage in reverse creation order and never panics.
func (g *gateway) close() {
	g.collect.Stop()
	if g.spool != nil {
		if err := g.spool.Close(); err != nil {
			g.log.Warn("spool close", "error", err.Error())
		}
	}
	if err := g.alerts.Close(); err != nil {
		g.log.Warn("alert store close", "error", err.Error())
	}
	if err := g.events.Close(); err != nil {
		g.log.Warn("event log close", "error", err.Error())
	}
	if err := g.audit.Close(); err != nil {
		g.log.Warn("audit log close", "error", err.Error())
	}
}

// runLoops drives the time-based detection, the spool drain and the site
// liveness state until ctx is cancelled.
func (g *gateway) runLoops(ctx context.Context) {
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	drain := time.NewTicker(10 * time.Second)
	defer drain.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			g.pipe.Tick(ctx)
		case <-drain.C:
			g.pipe.DrainSpool(ctx)
		}
	}
}

// detectionWorld satisfies detect.World by combining the registry read model
// with the current operator policy.
type detectionWorld struct {
	*state.Registry
	policy *policy.Manager
}

// Policy implements detect.World.
func (w detectionWorld) Policy() domain.Policy { return w.policy.Current() }

// otCatalogPath resolves the optional OT vendor catalog. It is optional: the
// discovery works without it and simply reports lower confidence.
func otCatalogPath() string {
	if p := os.Getenv("GEDEFENSE_OT_CATALOG"); p != "" {
		return p
	}
	candidates := []string{
		filepath.Join("data", "ot-catalog", "vendors.json"),
		filepath.Join("..", "..", "data", "ot-catalog", "vendors.json"),
		filepath.Join("..", "..", "..", "data", "ot-catalog", "vendors.json"),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

// demoSeedSite is used in demo mode to replace the configured site with the
// fictional demo store.
func (g *gateway) demoSeedSite() domain.Site { return demo.Site(g.clock.Now()) }
