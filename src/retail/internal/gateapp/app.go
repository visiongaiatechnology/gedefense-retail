// Package gateapp is the composition root of the GeDefense Retail Access Gate
// (retailgate). It wires the gate's identity, approval, storage, data-plane
// proxies, alerting/notification, fail-safe engine and HTTP API into one process.
//
// The gate is deliberately a separate service from the 0.1 monitoring gateway:
//   - the management/config path is enforced here (default-deny writes),
//   - the OT process communication is never touched,
//   - if this process stops, remote management is closed while the plant keeps
//     running autonomously.
package gateapp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
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
	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/targets"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
	"github.com/visiongaiatechnology/gedefense/retail/internal/version"
)

// Options configures the gate runtime.
type Options struct {
	// ConfigPath is the loaded gate.json path (used to resolve the policy file
	// relative to the configuration directory).
	ConfigPath string
	// Logger receives structured logs. Nil uses a JSON logger on stderr.
	Logger *slog.Logger
}

// Run starts the gate and blocks until ctx is cancelled.
func Run(ctx context.Context, cfg gateconfig.Config, opts Options) error {
	if ctx == nil {
		return errors.New("gateapp: nil context")
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	log := opts.Logger
	if log == nil {
		log = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}
	log = log.With("product", "GeDefense Retail Access Gate", "version", version.Version, "site", cfg.SiteID)

	gate, err := newGate(cfg, opts.ConfigPath, log)
	if err != nil {
		return err
	}
	defer gate.close()

	// Fail-closed startup: no valid policy / broken audit chain / unreadable
	// store means the gate does not start at all.
	if err := gate.checkStartup(); err != nil {
		return fmt.Errorf("gateapp: startup check failed: %w", err)
	}

	if err := gate.serve(ctx); err != nil {
		return err
	}
	<-ctx.Done()
	gate.shutdown()
	return nil
}

// gate is the fully wired runtime.
type gate struct {
	cfg        gateconfig.Config
	log        *slog.Logger
	clock      ports.Clock
	store      *store.Store
	policy     *policyHolder
	identity   *identity.Service
	approval   *approval.Service
	hub        *api.Hub
	alerts     *alert.Engine
	webhook    *notify.Webhook
	dispatcher *notify.Dispatcher
	escalator  *notify.Escalator
	failsafe   *failsafe.Engine
	fsState    atomic.Value // failsafe.Result
	targets    *targets.Registry
	api        *api.Server
	apiSrv     *http.Server
	apiLn      net.Listener
	audit      *auditSink
	auth       *browserAuth
	startedAt  time.Time
	loops      sync.WaitGroup
	stopOnce   sync.Once
}

// newGate opens storage and builds every component. It does not start listeners.
func newGate(cfg gateconfig.Config, configPath string, log *slog.Logger) (*gate, error) {
	dataDir := cfg.EffectiveDataDir()
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	policyPath := resolvePolicyPath(cfg, configPath)
	initial, err := gateconfig.LoadPolicy(policyPath)
	if err != nil {
		return nil, fmt.Errorf("load policy: %w", err)
	}
	if err := initial.Validate(); err != nil {
		return nil, fmt.Errorf("policy invalid: %w", err)
	}
	if !initial.DefaultDeny {
		return nil, errors.New("policy must set default_deny=true (default-deny is mandatory)")
	}

	st, err := store.Open(store.Options{
		Dir:   dataDir,
		Clock: systemClock{},
		Retention: store.Retention{
			PlanDays: 365, DenyDays: 180, AuditDays: 365,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}

	hub := api.NewHub()
	auditSink := newAuditSink(st)
	policy := newPolicyHolder(initial)

	idSvc, err := identity.New(identity.Options{
		Users:      cfg.Users,
		Clock:      systemClock{},
		TOTPWindow: 1,
		Lockout:    identity.DefaultLockoutPolicy(),
		Steps:      st,
	})
	if err != nil {
		_ = st.Close()
		return nil, fmt.Errorf("identity: %w", err)
	}

	approvalSvc, err := approval.NewService(approval.Options{
		SiteID:   cfg.SiteID,
		Clock:    systemClock{},
		Repo:     st,
		Policy:   policy.get,
		Target:   cfg.Target,
		Timeouts: cfg.Timeouts,
		Publish: func(ev domain.GateEvent) {
			hub.Publish(ev.Kind, ev)
			if err := st.AppendEvent(context.Background(), ev); err != nil {
				_ = err // event persistence is best effort; audit remains authoritative
			}
		},
	})
	if err != nil {
		_ = st.Close()
		return nil, fmt.Errorf("approval: %w", err)
	}

	// Notifier chain: webhook (if configured) -> dispatcher -> escalator.
	var sender notify.Notifier = nopNotifier{}
	var webhook *notify.Webhook
	if cfg.Notify.WebhookURL != "" {
		secret := []byte(cfg.Notify.HMACSecret)
		webhook, err = notify.NewWebhook(notify.WebhookConfig{
			URL:         cfg.Notify.WebhookURL,
			HMACSecret:  secret,
			Timeout:     time.Duration(cfg.Notify.TimeoutS) * time.Second,
			MaxAttempts: 5,
			BaseBackoff: 500 * time.Millisecond,
			MaxBackoff:  30 * time.Second,
		})
		if err != nil {
			_ = st.Close()
			return nil, fmt.Errorf("webhook: %w", err)
		}
		sender = webhook
	}
	dispatcher, err := notify.NewDispatcher(sender, notify.DispatcherConfig{QueueSize: 64, Workers: 2})
	if err != nil {
		_ = st.Close()
		return nil, fmt.Errorf("notify dispatcher: %w", err)
	}

	steps := make([]notify.EscalationStep, 0, len(cfg.Notify.Escalation))
	for _, s := range cfg.Notify.Escalation {
		steps = append(steps, notify.EscalationStep{AfterMinutes: s.AfterMinutes, Role: string(s.Role)})
	}
	escalator, err := notify.NewEscalator(systemClock{}, notify.EscalationConfig{
		Steps:          steps,
		DefaultChannel: "webhook",
		Channels:       map[string]notify.Notifier{"webhook": dispatcher},
		MinSeverity:    domain.SeverityHigh,
		MaxPending:     64,
	})
	if err != nil {
		_ = st.Close()
		return nil, fmt.Errorf("escalator: %w", err)
	}
	escNotifier := &escalatingNotifier{dispatcher: dispatcher, escalator: escalator, clock: systemClock{}}

	alerts, err := alert.New(alert.Options{
		Clock:       systemClock{},
		SiteID:      cfg.SiteID,
		Audit:       auditSink,
		Publisher:   alertPublisher{hub: hub},
		Notifier:    escNotifier,
		MinNotify:   policy.notifyThreshold(),
		DedupWindow: 5 * time.Minute,
		MaxTracked:  1024,
	})
	if err != nil {
		_ = st.Close()
		return nil, fmt.Errorf("alerting: %w", err)
	}

	fsEngine, err := failsafe.NewEngine(failsafe.Options{Clock: systemClock{}})
	if err != nil {
		_ = st.Close()
		return nil, fmt.Errorf("failsafe: %w", err)
	}

	auth := newBrowserAuth(idSvc, systemClock{}, time.Duration(cfg.Timeouts.SessionTTLS)*time.Second)

	return &gate{
		cfg: cfg, log: log, clock: systemClock{}, store: st, policy: policy,
		identity: idSvc, approval: approvalSvc, hub: hub, alerts: alerts,
		webhook: webhook, dispatcher: dispatcher, escalator: escalator,
		failsafe: fsEngine, targets: nil, audit: auditSink, auth: auth,
		startedAt: time.Now().UTC(),
	}, nil
}

// serve starts data plane, failsafe loops and the HTTP API.
func (g *gate) serve(ctx context.Context) error {
	// Data plane listeners are started first: without them the management path
	// is unreachable, which is safe, but useless.
	// Every denial must reach the alert engine (webhook/on-call), not only the
	// store. The wrapper keeps the proxies independent of the alerting package.
	sessionLookup := &alertingSessionLookup{approval: g.approval, alerts: g.alerts}
	tr, err := targets.New(targets.Options{
		Clock:             g.clock,
		ModbusSessions:    sessionLookup,
		HTTPSessions:      sessionLookup,
		HTTPAuth:          g.auth,
		SourceCIDRs:       g.cfg.SourceCIDRs,
		HTTPSecureCookies: false,
		HTTPBodyLimit:     128 << 10,
	})
	if err != nil {
		return fmt.Errorf("targets: %w", err)
	}
	g.targets = tr
	for _, t := range g.cfg.Targets {
		spec, err := specForTarget(t)
		if err != nil {
			return fmt.Errorf("target %q: %w", t.TargetID, err)
		}
		if err := tr.Add(spec); err != nil {
			return fmt.Errorf("target %q: %w", t.TargetID, err)
		}
	}
	if err := tr.Start(ctx); err != nil {
		return fmt.Errorf("start targets: %w", err)
	}

	server, err := api.New(api.Deps{
		Info: api.Info{
			Product:   "GeDefense Retail Access Gate",
			Version:   version.Version,
			Commit:    version.Commit,
			BuildDate: version.BuildDate,
		},
		Config:   g.cfg,
		Identity: g.identity,
		Gate:     g.approval,
		Stream:   g.hub,
		Targets:  g.targetStatus,
		Failsafe: g.failsafeState,
		NotifyTest: func(ctx context.Context) error {
			if g.webhook == nil {
				return errors.New("no webhook configured")
			}
			return g.webhook.SendTest(ctx, g.clock.Now(), g.cfg.SiteID)
		},
		LoadPolicy:     g.loadPolicy,
		ActivatePolicy: g.activatePolicy,
		Policy:         g.policy.get,
		Escalations: &api.EscalationHooks{
			List: g.listEscalations,
			Ack:  g.ackEscalation,
		},
	})
	if err != nil {
		return fmt.Errorf("api: %w", err)
	}
	g.api = server

	ln, err := net.Listen("tcp", g.cfg.Listen.API)
	if err != nil {
		return fmt.Errorf("listen api %q: %w", g.cfg.Listen.API, err)
	}
	g.apiLn = ln

	tlsCfg, err := buildServerTLS(g.cfg.Listen)
	if err != nil {
		_ = ln.Close()
		return fmt.Errorf("api tls: %w", err)
	}
	g.apiSrv = &http.Server{
		Handler:           server.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      0, // SSE streams arm per-write deadlines themselves
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(g.log.Handler(), slog.LevelWarn),
	}
	if tlsCfg != nil {
		ln = tls.NewListener(ln, tlsCfg)
	}
	g.loops.Add(1)
	go func() {
		defer g.loops.Done()
		if err := g.apiSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			g.log.Error("api server stopped", "error", err.Error())
		}
	}()

	g.dispatcher.Start(ctx)
	g.loops.Add(1)
	go func() {
		defer g.loops.Done()
		g.runLoops(ctx)
	}()
	g.log.Info("access gate started",
		"api", ln.Addr().String(), "targets", len(g.cfg.Targets),
		"users", len(g.cfg.Users), "policy_version", g.policy.get().Version)
	return nil
}

// runLoops drives fail-safe evaluation, escalation timers and retention.
func (g *gate) runLoops(ctx context.Context) {
	fsTick := time.NewTicker(10 * time.Second)
	defer fsTick.Stop()
	escTick := time.NewTicker(30 * time.Second)
	defer escTick.Stop()
	pruneTick := time.NewTicker(6 * time.Hour)
	defer pruneTick.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-fsTick.C:
			g.evaluateFailsafe()
		case <-escTick.C:
			g.escalator.Tick(g.clock.Now())
		case <-pruneTick.C:
			if _, err := g.store.Prune(ctx, g.clock.Now()); err != nil {
				g.log.Warn("gate retention prune failed", "error", err.Error())
			}
		}
	}
}

// evaluateFailsafe refreshes the fail-safe decision.
func (g *gate) evaluateFailsafe() {
	res := g.failsafe.Evaluate(failsafe.Dependencies{
		Audit:                g.audit.state(),
		PolicyReadable:       g.policy.get().PolicyID != "",
		PlanStoreReadable:    g.storeReadable(true),
		SessionStoreReadable: g.storeReadable(false),
		CoreAlive:            true,
		MonitoringAlive:      true, // the gate is independent of retaild
		UpstreamAlive:        g.upstreamHealthy(),
		NetworkSplit:         false,
	})
	g.fsState.Store(res)
	if res.CloseListeners && g.targets != nil {
		g.targets.Stop()
		g.log.Error("fail-safe closed the management data plane", "reason", res.DenyReason, "health", res.Health)
	}
	for _, n := range res.Notices {
		g.hub.Publish(domain.GateEventFailsafe, n)
	}
}

// checkStartup fails closed when the gate cannot guarantee a consistent state.
func (g *gate) checkStartup() error {
	if ok, seq, err := g.approval.VerifyAudit(context.Background()); err != nil || !ok {
		return fmt.Errorf("audit chain not verifiable (first failing seq %d): %v", seq, err)
	}
	if err := g.failsafe.CheckStartup(failsafe.Dependencies{
		Audit:                failsafe.AuditOK,
		PolicyReadable:       true,
		PlanStoreReadable:    g.storeReadable(true),
		SessionStoreReadable: g.storeReadable(false),
		CoreAlive:            true,
	}); err != nil {
		return err
	}
	g.evaluateFailsafe()
	return nil
}

// shutdown stops everything in reverse order, bounded in time.
func (g *gate) shutdown() {
	g.stopOnce.Do(func() {
		g.log.Info("access gate shutting down")
		if g.targets != nil {
			g.targets.Stop()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if g.apiSrv != nil {
			if err := g.apiSrv.Shutdown(ctx); err != nil {
				g.log.Warn("api shutdown incomplete", "error", err.Error())
				_ = g.apiSrv.Close()
			}
		}
		if g.dispatcher != nil {
			g.dispatcher.Stop()
		}
		if g.escalator != nil {
			g.escalator.Stop()
		}
		g.loops.Wait()
	})
}

// close releases storage after shutdown.
func (g *gate) close() {
	g.shutdown()
	if g.store != nil {
		if err := g.store.Close(); err != nil {
			g.log.Warn("gate store close failed", "error", err.Error())
		}
	}
}
