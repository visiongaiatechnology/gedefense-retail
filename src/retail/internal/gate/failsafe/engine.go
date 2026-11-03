package failsafe

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
)

// Startup errors. The gate refuses to start instead of running without a
// trustworthy authorization/audit basis (fail-closed).
var (
	ErrPolicyUnreadable = errors.New("failsafe: policy unreadable or missing; gate start refused")
	ErrStoreCorrupt     = errors.New("failsafe: plan/session store corrupt; gate start refused")
	ErrAuditUnavailable = errors.New("failsafe: audit store unavailable or full; gate start refused")
)

// AuditState is the injected health of the audit store. AuditAppendFailing means
// an append was just refused (disk error); AuditFull means the retention/size
// bound is exhausted. Both make writes fail closed.
type AuditState string

const (
	AuditOK            AuditState = "ok"
	AuditAppendFailing AuditState = "append_failing"
	AuditFull          AuditState = "full"
)

// Dependencies is one injected snapshot of the gate's dependencies. The zero
// value is deliberately fail-closed: all booleans false and Audit == "" (not OK).
type Dependencies struct {
	Audit                AuditState `json:"audit"`
	PolicyReadable       bool       `json:"policy_readable"`
	PlanStoreReadable    bool       `json:"plan_store_readable"`
	SessionStoreReadable bool       `json:"session_store_readable"`
	CoreAlive            bool       `json:"core_alive"`
	MonitoringAlive      bool       `json:"monitoring_alive"`
	UpstreamAlive        bool       `json:"upstream_alive"`
	NetworkSplit         bool       `json:"network_split"`
}

// HealthyDependencies returns the all-green snapshot (tests, status probes).
func HealthyDependencies() Dependencies {
	return Dependencies{
		Audit:                AuditOK,
		PolicyReadable:       true,
		PlanStoreReadable:    true,
		SessionStoreReadable: true,
		CoreAlive:            true,
		MonitoringAlive:      true,
		UpstreamAlive:        true,
	}
}

// ClockState is the stability of the gate clock after jump detection.
type ClockState string

const (
	ClockStable   ClockState = "stable"
	ClockUnstable ClockState = "unstable"
)

// Notice is one alert notice the caller forwards to the alert/notify pipeline.
type Notice struct {
	Condition Condition       `json:"condition"`
	Severity  domain.Severity `json:"severity"`
	Code      string          `json:"code"`
	Message   string          `json:"message"`
}

// Result is the combined fail-safe decision of one evaluation.
type Result struct {
	AllowWrite        bool        `json:"allow_write"`
	CloseListeners    bool        `json:"close_listeners"`
	APIUp             bool        `json:"api_up"`
	FailsafeActive    bool        `json:"failsafe_active"`
	Health            string      `json:"health"` // ok | degraded | blocked | stopped
	DenyReason        string      `json:"deny_reason,omitempty"`
	Clock             ClockState  `json:"clock"`
	Active            []Condition `json:"active_conditions,omitempty"`
	Decisions         []Decision  `json:"decisions,omitempty"`
	Notices           []Notice    `json:"notices,omitempty"`
	ColdChainAffected bool        `json:"cold_chain_affected"` // always false
}

// Options configures clock-jump detection.
type Options struct {
	// Clock is mandatory and injectable.
	Clock ports.Clock
	// MaxForwardJump is the largest plausible forward step (default 2 min).
	MaxForwardJump time.Duration
	// MaxBackwardJump tolerates small backwards corrections (default 5 s).
	MaxBackwardJump time.Duration
	// StableObservations is the number of consecutive plausible observations
	// required before writes are allowed again (default 2).
	StableObservations int
}

func (opts Options) normalize() (Options, error) {
	if opts.Clock == nil {
		return Options{}, errors.New("failsafe: clock is required")
	}
	if opts.MaxForwardJump == 0 {
		opts.MaxForwardJump = 2 * time.Minute
	}
	if opts.MaxForwardJump < time.Second || opts.MaxForwardJump > time.Hour {
		return Options{}, fmt.Errorf("failsafe: max forward jump must be in [1s, 1h]")
	}
	if opts.MaxBackwardJump == 0 {
		opts.MaxBackwardJump = 5 * time.Second
	}
	if opts.MaxBackwardJump < 0 || opts.MaxBackwardJump > time.Minute {
		return Options{}, fmt.Errorf("failsafe: max backward jump must be in [0, 1m]")
	}
	if opts.StableObservations == 0 {
		opts.StableObservations = 2
	}
	if opts.StableObservations < 1 || opts.StableObservations > 10 {
		return Options{}, fmt.Errorf("failsafe: stable observations must be in [1, 10]")
	}
	return opts, nil
}

// Engine evaluates the fail-safe matrix against injected dependencies and
// tracks clock stability. It is safe for concurrent use.
type Engine struct {
	mu       sync.Mutex
	clock    ports.Clock
	opts     Options
	lastNow  time.Time
	unstable bool
	stable   int
}

// NewEngine validates the options and creates the fail-safe engine.
func NewEngine(opts Options) (*Engine, error) {
	normalized, err := opts.normalize()
	if err != nil {
		return nil, err
	}
	return &Engine{clock: normalized.Clock, opts: normalized}, nil
}

// ClockState reports the current clock stability.
func (e *Engine) ClockState() ClockState {
	if e == nil {
		return ClockUnstable
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.stateLocked()
}

// ObserveClock feeds one clock observation (health probe/tick) and reports the
// resulting stability. A jump marks the clock unstable; consecutive plausible
// observations clear it.
func (e *Engine) ObserveClock(now time.Time) ClockState {
	if e == nil {
		return ClockUnstable
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.observeLocked(now.UTC())
}

// Evaluate combines all active matrix rows into one decision. The result never
// reports ColdChainAffected=true.
func (e *Engine) Evaluate(deps Dependencies) Result {
	if e == nil {
		return stoppedResult()
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	clock := e.observeLocked(e.clock.Now().UTC())
	result := Result{
		AllowWrite:        true,
		APIUp:             true,
		Health:            "ok",
		Clock:             clock,
		ColdChainAffected: false,
	}
	for _, decision := range Decisions() {
		if !conditionActive(decision.Condition, deps, clock) {
			continue
		}
		result.Active = append(result.Active, decision.Condition)
		result.Decisions = append(result.Decisions, decision)
		if !decision.AllowWrite {
			result.AllowWrite = false
		}
		if decision.CloseListeners {
			result.CloseListeners = true
		}
		if !decision.APIUp {
			result.APIUp = false
		}
		if result.DenyReason == "" && decision.DenyReason != "" {
			result.DenyReason = decision.DenyReason
		}
		result.Health = worseHealth(result.Health, decision.Health)
		if decision.Alert {
			result.Notices = append(result.Notices, Notice{
				Condition: decision.Condition,
				Severity:  decision.Severity,
				Code:      string(decision.Condition),
				Message:   decision.Note,
			})
		}
	}
	result.FailsafeActive = !result.AllowWrite || clock == ClockUnstable
	return result
}

// CheckStartup applies the fail-closed startup rules: without readable policy,
// readable plan/session stores and a usable audit store the gate must not start.
func (e *Engine) CheckStartup(deps Dependencies) error {
	if !deps.PolicyReadable {
		return ErrPolicyUnreadable
	}
	if !deps.PlanStoreReadable || !deps.SessionStoreReadable {
		return ErrStoreCorrupt
	}
	if deps.Audit != AuditOK {
		return ErrAuditUnavailable
	}
	return nil
}

func (e *Engine) stateLocked() ClockState {
	if e.unstable {
		return ClockUnstable
	}
	return ClockStable
}

func (e *Engine) observeLocked(now time.Time) ClockState {
	if now.IsZero() {
		e.unstable = true
		return ClockUnstable
	}
	if e.lastNow.IsZero() {
		e.lastNow = now
		return e.stateLocked()
	}
	delta := now.Sub(e.lastNow)
	if delta < -e.opts.MaxBackwardJump || delta > e.opts.MaxForwardJump {
		e.unstable = true
		e.stable = 0
	} else if e.unstable {
		e.stable++
		if e.stable >= e.opts.StableObservations {
			e.unstable = false
			e.stable = 0
		}
	}
	e.lastNow = now
	return e.stateLocked()
}

func conditionActive(condition Condition, deps Dependencies, clock ClockState) bool {
	switch condition {
	case CondAuditStoreFailure:
		return deps.Audit == AuditAppendFailing
	case CondAuditStoreFull:
		return deps.Audit == AuditFull
	case CondClockJump:
		return clock == ClockUnstable
	case CondPolicyUnreadable:
		return !deps.PolicyReadable
	case CondPlanStoreCorrupt:
		return !deps.PlanStoreReadable
	case CondSessionStoreCorrupt:
		return !deps.SessionStoreReadable
	case CondGateCoreDown:
		return !deps.CoreAlive
	case CondMonitoringDown:
		return !deps.MonitoringAlive
	case CondUpstreamDown:
		return !deps.UpstreamAlive && !deps.NetworkSplit
	case CondNetworkSplit:
		return deps.NetworkSplit
	default:
		return false
	}
}

func healthRank(health string) int {
	switch health {
	case "ok":
		return 0
	case "degraded":
		return 1
	case "blocked":
		return 2
	case "stopped":
		return 3
	default:
		return 1
	}
}

func worseHealth(a, b string) string {
	if healthRank(b) > healthRank(a) {
		return b
	}
	return a
}

func stoppedResult() Result {
	decision, _ := DecisionFor(CondGateCoreDown)
	return Result{
		AllowWrite:        false,
		CloseListeners:    true,
		APIUp:             false,
		FailsafeActive:    true,
		Health:            "stopped",
		Clock:             ClockUnstable,
		Active:            []Condition{CondGateCoreDown},
		Decisions:         []Decision{decision},
		ColdChainAffected: false,
		Notices: []Notice{{
			Condition: CondGateCoreDown,
			Severity:  decision.Severity,
			Code:      string(CondGateCoreDown),
			Message:   decision.Note,
		}},
	}
}
