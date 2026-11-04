// Setpoint integrity worker and automatic recovery (Gate 0.3).
//
// The worker periodically reads explicitly configured reference registers and
// records a hash-chained audit event when a confirmed mismatch is observed.
// Automatic recovery is opt-in (global + per reference), writes only the
// configured reference raw value via FC6, and never retries an unclear outcome.
package gateapp

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/api"
	gateconfig "github.com/visiongaiatechnology/gedefense/retail/internal/gate/config"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
)

// Integrity audit actions (stable identifiers for runbooks/UI).
const (
	ActionIntegrityMismatch = "gate.integrity.mismatch"
	ActionIntegrityRestored = "gate.integrity.restored"
	ActionRecoveryIntent    = "gate.recovery.intent"
	ActionRecoveryApplied   = "gate.recovery.applied"
	ActionRecoveryFailed    = "gate.recovery.failed"
	ActionRecoveryUnknown   = "gate.recovery.unknown"
)

const integrityDeviceTimeout = 5 * time.Second

// deviceConn is the minimal device contract used by the worker (fake in tests).
type deviceConn interface {
	ReadHoldingRegister(ctx context.Context, register uint16) (uint16, error)
	WriteSingleRegister(ctx context.Context, register, value uint16) error
	Close() error
}

// integrityDeps are the worker's injected world.
type integrityDeps struct {
	cfg     gateconfig.IntegrityConfig
	targets map[domain.TargetID]gateconfig.Target
	clock   ports.Clock
	open    func(target gateconfig.Target, unitID uint8) (deviceConn, error)
	audit   func(ctx context.Context, action, objectID, reason string) error
	active  func(ctx context.Context, target domain.TargetID) (bool, error)
	publish func(status api.IntegrityStatus)
	log     *slog.Logger
	// allowWrite reports whether the fail-safe currently allows writes. The
	// worker performs no device I/O while this returns false (nil = allow).
	allowWrite func() bool
}

// writeAllowed is fail-closed: an explicit false blocks all device I/O.
func (w *integrityWorker) writeAllowed() bool {
	if w.deps.allowWrite == nil {
		return true
	}
	return w.deps.allowWrite()
}

type integrityRefState struct {
	ref    gateconfig.IntegrityReference
	target gateconfig.Target

	state       string // ok|mismatch|unreadable|stale
	current     string
	lastRead    time.Time
	confirmed   int
	audited     bool // mismatch audit already emitted for this episode
	attempted   bool // recovery attempted for this confirmed mismatch
	lastAttempt time.Time
	lastResult  string
	cooldown    time.Time
}

// integrityWorker polls references and performs bounded automatic recovery.
type integrityWorker struct {
	deps    integrityDeps
	mu      sync.Mutex
	refs    []*integrityRefState
	actions []time.Time // recovery write attempts (hour/day limits)
}

// newIntegrityWorker builds the worker from an effective integrity config.
func newIntegrityWorker(deps integrityDeps) *integrityWorker {
	worker := &integrityWorker{deps: deps}
	if deps.clock == nil {
		worker.deps.clock = realIntegrityClock{}
	}
	for _, ref := range deps.cfg.References {
		target, ok := deps.targets[ref.TargetID]
		if !ok {
			continue
		}
		worker.refs = append(worker.refs, &integrityRefState{ref: ref, target: target, state: "stale"})
	}
	return worker
}

type realIntegrityClock struct{}

func (realIntegrityClock) Now() time.Time { return time.Now().UTC() }

// Run polls until the context is cancelled.
func (w *integrityWorker) Run(ctx context.Context) {
	if !w.deps.cfg.Enabled {
		return
	}
	interval := time.Duration(w.deps.cfg.PollIntervalS) * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	w.runOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.runOnce(ctx)
		}
	}
}

// runOnce performs one poll cycle for every reference.
func (w *integrityWorker) runOnce(ctx context.Context) {
	for _, ref := range w.refs {
		w.pollReference(ctx, ref)
	}
	w.publish()
}

// pollReference reads one reference and drives state/audit/recovery.
func (w *integrityWorker) pollReference(ctx context.Context, ref *integrityRefState) {
	if !w.writeAllowed() {
		// Fail-safe active: no device I/O and no audit while the gate must not
		// write; the reference is reported stale.
		w.mu.Lock()
		ref.state = "stale"
		w.mu.Unlock()
		return
	}
	now := w.deps.clock.Now().UTC()
	expected, ok := expectedRaw(ref.ref)
	if !ok {
		w.setState(ref, "unreadable", now)
		return
	}
	unit := refUnit(ref)
	actual, err := w.readRaw(ctx, ref, unit)
	if err != nil {
		w.deps.log.Warn("integrity read failed", "target", ref.ref.TargetID, "register", ref.ref.Register, "error", err.Error())
		w.mu.Lock()
		ref.state = "unreadable"
		ref.lastRead = now
		ref.current = ""
		ref.confirmed = 0
		ref.audited = false
		w.mu.Unlock()
		return
	}
	w.mu.Lock()
	ref.lastRead = now
	ref.current = formatDisplay(actual, ref.ref.Scale)
	if actual == expected {
		wasMismatch := ref.state == "mismatch"
		ref.state = "ok"
		ref.confirmed = 0
		ref.audited = false
		ref.attempted = false
		w.mu.Unlock()
		if wasMismatch {
			_ = w.audit(ctx, ActionIntegrityRestored, ref, fmt.Sprintf("register=%d current=%d expected=%d", ref.ref.Register, actual, expected))
		}
		return
	}
	ref.state = "mismatch"
	ref.confirmed++
	confirm := w.deps.cfg.ConfirmReads
	confirmedNow := ref.confirmed >= confirm
	needAudit := confirmedNow && !ref.audited
	if needAudit {
		ref.audited = true
	}
	shouldRecover := confirmedNow && w.deps.cfg.Recovery.Enabled && ref.ref.Recovery && !ref.attempted
	w.mu.Unlock()
	auditOK := true
	if needAudit {
		// Audit-fail-closed: without the hash-chained mismatch evidence no
		// recovery may be attempted in this cycle.
		if err := w.audit(ctx, ActionIntegrityMismatch, ref,
			fmt.Sprintf("register=%d current=%d expected=%d confirmed_reads=%d", ref.ref.Register, actual, expected, ref.confirmed)); err != nil {
			auditOK = false
		}
	}
	if shouldRecover && auditOK {
		w.recover(ctx, ref, expected, unit)
	}
	w.publish()
}

// recover performs one bounded recovery attempt. It never retries.
func (w *integrityWorker) recover(ctx context.Context, ref *integrityRefState, expected uint16, unit uint8) {
	if !w.writeAllowed() {
		return
	}
	now := w.deps.clock.Now().UTC()
	requireNoActive := w.deps.cfg.Recovery.RequireNoActiveWindow == nil || *w.deps.cfg.Recovery.RequireNoActiveWindow
	if requireNoActive && w.deps.active != nil {
		active, err := w.deps.active(ctx, ref.ref.TargetID)
		if err != nil || active {
			w.deps.log.Warn("integrity recovery blocked", "target", ref.ref.TargetID, "active", active, "error", errText(err))
			return
		}
	}
	w.mu.Lock()
	if now.Before(ref.cooldown) {
		w.mu.Unlock()
		return
	}
	w.pruneActionsLocked(now)
	if w.countActionsLocked(time.Hour) >= w.deps.cfg.Recovery.MaxActionsPerHour ||
		w.countActionsLocked(24*time.Hour) >= w.deps.cfg.Recovery.MaxActionsPerDay {
		w.mu.Unlock()
		w.deps.log.Warn("integrity recovery rate limit reached", "target", ref.ref.TargetID)
		return
	}
	ref.attempted = true
	ref.lastAttempt = now
	w.actions = append(w.actions, now)
	w.mu.Unlock()

	// F-A3-02: audit the recovery intent BEFORE any write. An audit failure
	// aborts the attempt without touching the device.
	if err := w.audit(ctx, ActionRecoveryIntent, ref,
		fmt.Sprintf("register=%d expected=%d", ref.ref.Register, expected)); err != nil {
		w.mu.Lock()
		ref.lastResult = "blocked"
		ref.cooldown = now.Add(time.Duration(w.deps.cfg.Recovery.CooldownS) * time.Second)
		w.mu.Unlock()
		w.deps.log.Error("integrity recovery intent audit failed; no write", "target", ref.ref.TargetID, "error", err.Error())
		w.publish()
		return
	}
	// Fail-safe may change between the poll read and the recovery write.
	if !w.writeAllowed() {
		return
	}
	conn, err := w.deps.open(ref.target, unit)
	if err != nil {
		w.finishRecovery(ctx, ref, "unknown", ActionRecoveryUnknown, err)
		return
	}
	// F-A3-03: immediate re-read before the FC6 write. If the value already
	// matches the reference (or cannot be read), no write is sent.
	current, rerr := conn.ReadHoldingRegister(ctx, uint16(ref.ref.Register-40001))
	if rerr != nil {
		_ = conn.Close()
		w.finishRecovery(ctx, ref, "unknown", ActionRecoveryUnknown, rerr)
		return
	}
	if current == expected {
		_ = conn.Close()
		w.mu.Lock()
		ref.state = "ok"
		ref.current = formatDisplay(expected, ref.ref.Scale)
		ref.confirmed = 0
		ref.audited = false
		ref.lastResult = "restored"
		w.mu.Unlock()
		_ = w.audit(ctx, ActionIntegrityRestored, ref,
			fmt.Sprintf("register=%d current=%d expected=%d reread=stable", ref.ref.Register, current, expected))
		w.publish()
		return
	}
	if err := conn.WriteSingleRegister(ctx, uint16(ref.ref.Register-40001), expected); err != nil {
		_ = conn.Close()
		w.finishRecovery(ctx, ref, "unknown", ActionRecoveryUnknown, err)
		return
	}
	readback, rerr := conn.ReadHoldingRegister(ctx, uint16(ref.ref.Register-40001))
	_ = conn.Close()
	if rerr != nil {
		w.finishRecovery(ctx, ref, "unknown", ActionRecoveryUnknown, rerr)
		return
	}
	if readback != expected {
		w.finishRecovery(ctx, ref, "failed", ActionRecoveryFailed,
			fmt.Errorf("readback=%d expected=%d", readback, expected))
		return
	}
	// Post-write audit is fail-closed: if the applied evidence cannot be
	// written, the outcome stays unknown and is never retried.
	if err := w.audit(ctx, ActionRecoveryApplied, ref,
		fmt.Sprintf("register=%d value=%d readback=%d", ref.ref.Register, expected, readback)); err != nil {
		w.mu.Lock()
		ref.lastResult = "unknown"
		ref.state = "mismatch"
		ref.cooldown = now.Add(time.Duration(w.deps.cfg.Recovery.CooldownS) * time.Second)
		w.mu.Unlock()
		w.deps.log.Error("integrity recovery applied-audit failed; outcome unknown, no retry", "target", ref.ref.TargetID, "error", err.Error())
		w.publish()
		return
	}
	w.mu.Lock()
	ref.state = "ok"
	ref.current = formatDisplay(expected, ref.ref.Scale)
	ref.confirmed = 0
	ref.audited = false
	ref.lastResult = "applied"
	ref.cooldown = now.Add(time.Duration(w.deps.cfg.Recovery.CooldownS) * time.Second)
	w.mu.Unlock()
	w.publish()
}

// finishRecovery records a failed/unknown recovery outcome and sets the cooldown.
func (w *integrityWorker) finishRecovery(ctx context.Context, ref *integrityRefState, result, action string, cause error) {
	now := w.deps.clock.Now().UTC()
	w.mu.Lock()
	ref.lastResult = result
	ref.cooldown = now.Add(time.Duration(w.deps.cfg.Recovery.CooldownS) * time.Second)
	w.mu.Unlock()
	_ = w.audit(ctx, action, ref, cause.Error())
	w.deps.log.Warn("integrity recovery not applied", "target", ref.ref.TargetID, "register", ref.ref.Register, "result", result, "error", cause.Error())
	w.publish()
}

// readRaw opens a short-lived device connection and reads the reference register.
func (w *integrityWorker) readRaw(ctx context.Context, ref *integrityRefState, unit uint8) (uint16, error) {
	conn, err := w.deps.open(ref.target, unit)
	if err != nil {
		return 0, err
	}
	defer func() { _ = conn.Close() }()
	return conn.ReadHoldingRegister(ctx, uint16(ref.ref.Register-40001))
}

func (w *integrityWorker) setState(ref *integrityRefState, state string, now time.Time) {
	w.mu.Lock()
	ref.state = state
	ref.lastRead = now
	w.mu.Unlock()
}

// audit writes one hash-chained integrity audit entry. The error is returned so
// write-critical callers can fail closed (no write without audit evidence).
func (w *integrityWorker) audit(ctx context.Context, action string, ref *integrityRefState, reason string) error {
	if w.deps.audit == nil {
		return nil
	}
	objectID := fmt.Sprintf("%s/%d", ref.ref.TargetID, ref.ref.Register)
	if err := w.deps.audit(ctx, action, objectID, reason); err != nil {
		w.deps.log.Error("integrity audit failed", "action", action, "error", err.Error())
		return err
	}
	return nil
}

func (w *integrityWorker) publish() {
	if w.deps.publish == nil {
		return
	}
	w.deps.publish(w.Status())
}

// Status returns a consistent read-only snapshot for the API/SSE.
func (w *integrityWorker) Status() api.IntegrityStatus {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := w.deps.clock.Now().UTC()
	out := api.IntegrityStatus{
		Enabled:    w.deps.cfg.Enabled,
		IntervalS:  w.deps.cfg.PollIntervalS,
		References: make([]api.IntegrityReferenceStatus, 0, len(w.refs)),
		Recovery: api.IntegrityRecoveryStatus{
			Enabled:         w.deps.cfg.Recovery.Enabled,
			ActionsLastHour: w.countActionsLocked(time.Hour),
			ActionsLastDay:  w.countActionsLocked(24 * time.Hour),
		},
	}
	for _, ref := range w.refs {
		state := ref.state
		if ref.lastRead.IsZero() || now.Sub(ref.lastRead) > time.Duration(w.deps.cfg.StaleAfterS)*time.Second {
			state = "stale"
		}
		item := api.IntegrityReferenceStatus{
			TargetID:            string(ref.ref.TargetID),
			FC:                  ref.ref.FC,
			Register:            ref.ref.Register,
			Unit:                ref.ref.Unit,
			Reference:           ref.ref.Value,
			Current:             ref.current,
			State:               state,
			ConfirmedMismatches: ref.confirmed,
			Recovery: api.IntegrityRecoveryRefStatus{
				Enabled:    ref.ref.Recovery,
				LastResult: ref.lastResult,
			},
		}
		if !ref.lastRead.IsZero() {
			item.LastReadAt = ref.lastRead.Format(time.RFC3339)
		}
		if !ref.lastAttempt.IsZero() {
			item.Recovery.LastAttemptAt = ref.lastAttempt.Format(time.RFC3339)
		}
		if now.Before(ref.cooldown) {
			item.Recovery.CooldownUntil = ref.cooldown.Format(time.RFC3339)
		}
		out.References = append(out.References, item)
	}
	return out
}

func (w *integrityWorker) pruneActionsLocked(now time.Time) {
	cutoff := now.Add(-24 * time.Hour)
	kept := w.actions[:0]
	for _, at := range w.actions {
		if at.After(cutoff) {
			kept = append(kept, at)
		}
	}
	w.actions = kept
}

func (w *integrityWorker) countActionsLocked(window time.Duration) int {
	cutoff := w.deps.clock.Now().UTC().Add(-window)
	count := 0
	for _, at := range w.actions {
		if at.After(cutoff) {
			count++
		}
	}
	return count
}

// refUnit returns the reference unit id, falling back to the target unit.
func refUnit(ref *integrityRefState) uint8 {
	if ref.ref.UnitID > 0 && ref.ref.UnitID <= 255 {
		return uint8(ref.ref.UnitID)
	}
	if ref.target.UnitID > 0 && ref.target.UnitID <= 255 {
		return uint8(ref.target.UnitID)
	}
	return 1
}

// expectedRaw converts the operator-facing reference value to the wire value.
func expectedRaw(ref gateconfig.IntegrityReference) (uint16, bool) {
	display, err := strconv.ParseFloat(strings.TrimSpace(ref.Value), 64)
	if err != nil || math.IsNaN(display) || math.IsInf(display, 0) {
		return 0, false
	}
	scale := ref.Scale
	if scale <= 0 {
		scale = 1
	}
	raw := math.Round(display / scale)
	if raw < 0 || raw > 65535 {
		return 0, false
	}
	return uint16(raw), true
}

// formatDisplay formats a raw value as operator-facing display value.
func formatDisplay(raw uint16, scale float64) string {
	if scale <= 0 {
		scale = 1
	}
	display := float64(raw) * scale
	if math.Abs(display-math.Round(display)) < 1e-9 {
		return strconv.FormatInt(int64(math.Round(display)), 10)
	}
	return strconv.FormatFloat(display, 'f', -1, 64)
}
