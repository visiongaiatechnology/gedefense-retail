// Gate wiring for the setpoint integrity worker (lifecycle, active-session
// guard and the production device connection factory).
package gateapp

import (
	"context"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/api"
	gateconfig "github.com/visiongaiatechnology/gedefense/retail/internal/gate/config"
	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/deviceio"
	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/failsafe"
)

// openIntegrityDevice is the production device connection factory.
func openIntegrityDevice(target gateconfig.Target, unitID uint8) (deviceConn, error) {
	cfg := deviceio.Config{Addr: target.Upstream, UnitID: unitID, Timeout: integrityDeviceTimeout}
	client, err := deviceio.Dial(context.Background(), cfg)
	if err != nil {
		return nil, err
	}
	return client, nil
}

// startIntegrity builds and launches the integrity worker (gate 0.3).
func (g *gate) startIntegrity(ctx context.Context) {
	targetsByID := make(map[domain.TargetID]gateconfig.Target, len(g.cfg.Targets))
	for _, target := range g.cfg.Targets {
		targetsByID[target.TargetID] = target
	}
	// Populate the fail-safe state before the worker's first poll so the
	// allowWrite guard is meaningful from the very first cycle.
	g.evaluateFailsafe()
	worker := newIntegrityWorker(integrityDeps{
		cfg:     g.cfg.EffectiveIntegrity(),
		targets: targetsByID,
		clock:   g.clock,
		open:    openIntegrityDevice,
		audit: func(ctx context.Context, action, objectID, reason string) error {
			return g.approval.RecordAudit(ctx, "system", "gate-integrity", action, "gate_integrity", objectID, reason)
		},
		active: g.integrityActive,
		publish: func(status api.IntegrityStatus) {
			g.hub.Publish(domain.GateEventKind("gate_integrity"), status)
		},
		log: g.log,
		// F-A3-01: fail-closed guard. No device I/O (read or recovery write)
		// while the fail-safe is active or writes are not allowed.
		allowWrite: func() bool {
			value := g.fsState.Load()
			if value == nil {
				return false
			}
			result, ok := value.(failsafe.Result)
			if !ok {
				return false
			}
			return !result.FailsafeActive && result.AllowWrite
		},
	})
	g.integrity = worker
	g.loops.Add(1)
	go func() {
		defer g.loops.Done()
		worker.Run(ctx)
	}()
}

// sessionBlocksRecovery reports whether any non-revoked, non-expired session
// exists for the target (F-A3-04: consumed/in-flight sessions also block).
func sessionBlocksRecovery(sessions []domain.WriteSession, target domain.TargetID, now time.Time) bool {
	for _, session := range sessions {
		if session.TargetID == target && !session.Revoked && now.Before(session.ExpiresAt) {
			return true
		}
	}
	return false
}

// integrityActive reports an active approved plan window or write session for
// the target (recovery is blocked while an operator is actively writing).
func (g *gate) integrityActive(ctx context.Context, target domain.TargetID) (bool, error) {
	now := g.clock.Now().UTC()
	sessions, err := g.approval.ListSessions(ctx)
	if err != nil {
		return false, err
	}
	if sessionBlocksRecovery(sessions, target, now) {
		return true, nil
	}
	plans, err := g.approval.ListPlans(ctx)
	if err != nil {
		return false, err
	}
	for _, plan := range plans {
		if plan.TargetID == target && plan.State == domain.PlanApproved && plan.InWindow(now) {
			return true, nil
		}
	}
	return false, nil
}
