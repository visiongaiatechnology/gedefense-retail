package gateapp

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/api"
	gateconfig "github.com/visiongaiatechnology/gedefense/retail/internal/gate/config"
	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/failsafe"
)

// resolvePolicyPath resolves the policy file relative to the config directory.
func resolvePolicyPath(cfg gateconfig.Config, configPath string) string {
	name := cfg.PolicyFile
	if name == "" {
		name = "gate-policy.json"
	}
	if filepath.IsAbs(name) {
		return name
	}
	base := filepath.Dir(configPath)
	if configPath == "" || base == "." {
		base = "."
	}
	return filepath.Join(base, name)
}

// buildServerTLS returns nil for plain HTTP, or a TLS config for the API.
func buildServerTLS(l gateconfig.Listen) (*tls.Config, error) {
	if l.TLSCertFile == "" && l.TLSKeyFile == "" {
		if l.RequireClientCert {
			return nil, errors.New("require_client_cert needs tls_cert_file/tls_key_file")
		}
		return nil, nil
	}
	if l.TLSCertFile == "" || l.TLSKeyFile == "" {
		return nil, errors.New("tls_cert_file and tls_key_file must be configured together")
	}
	cert, err := tls.LoadX509KeyPair(l.TLSCertFile, l.TLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load server certificate: %w", err)
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}
	if l.RequireClientCert {
		pem, rerr := os.ReadFile(l.ClientCAFile)
		if rerr != nil {
			return nil, fmt.Errorf("read client CA: %w", rerr)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("client CA file contains no certificate")
		}
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
		cfg.ClientCAs = pool
	}
	return cfg, nil
}

// --- small helpers -------------------------------------------------------

func (g *gate) failsafeState() (bool, string) {
	v, ok := g.fsState.Load().(failsafe.Result)
	if !ok {
		return false, ""
	}
	return v.FailsafeActive, v.DenyReason
}

func (g *gate) storeReadable(plans bool) bool {
	if plans {
		_, err := g.store.ListPlans(context.Background())
		return err == nil
	}
	_, err := g.store.ListSessions(context.Background())
	return err == nil
}

func (g *gate) upstreamHealthy() bool {
	if g.targets == nil {
		return false
	}
	for _, h := range g.targets.Health() {
		if h.State != "listening" {
			return false
		}
	}
	return true
}

func (g *gate) targetStatus() []gateconfig.TargetStatus {
	out := make([]gateconfig.TargetStatus, 0, len(g.cfg.Targets))
	if g.targets == nil {
		return out
	}
	for _, h := range g.targets.Health() {
		out = append(out, gateconfig.TargetStatus{TargetID: h.TargetID, Protocol: h.Protocol, State: h.State})
	}
	return out
}

func (g *gate) loadPolicy() (gateconfig.Policy, error) {
	return gateconfig.LoadPolicy(resolvePolicyPath(g.cfg, g.cfg.PolicyFile))
}

func (g *gate) activatePolicy(p gateconfig.Policy) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if !p.DefaultDeny {
		return errors.New("policy must keep default_deny=true")
	}
	cur := g.policy.get()
	if p.Version <= cur.Version {
		return fmt.Errorf("policy version must increase (current %d)", cur.Version)
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("policy hash: %w", err)
	}
	sum := sha256.Sum256(raw)
	g.policy.set(p)
	g.approval.RecordAudit(context.Background(), "system", "master_admin", "gate.policy.reload", "gate_policy",
		p.PolicyID, "version "+fmt.Sprint(p.Version)+" hash "+hex.EncodeToString(sum[:]))
	g.hub.Publish(domain.GateEventKind("policy_reloaded"), map[string]any{"version": p.Version, "policy_id": p.PolicyID})
	return nil
}

func (g *gate) listEscalations() []api.EscalationView {
	pending := g.escalator.Pending()
	out := make([]api.EscalationView, 0, len(pending))
	for _, p := range pending {
		out = append(out, api.EscalationView{
			NotificationID: p.NotificationID,
			Severity:       p.Severity,
			CreatedAt:      p.TrackedAt,
			Level:          p.NextStep,
			Delivered:      p.Escalations > 0,
			Acked:          p.Acked,
			AckedBy:        p.AckedBy,
			AckedAt:        p.AckedAt,
		})
	}
	return out
}

func (g *gate) ackEscalation(_ context.Context, notificationID, actor, note string) (api.EscalationView, error) {
	// Capture the operator-visible context (severity, creation time) before the
	// ack removes the notification from the pending list.
	var severity domain.Severity
	var createdAt time.Time
	var level int
	for _, pending := range g.escalator.Pending() {
		if pending.NotificationID == notificationID {
			severity = pending.Severity
			createdAt = pending.TrackedAt
			level = pending.NextStep
			break
		}
	}
	rec, ok := g.escalator.Ack(notificationID, actor, g.clock.Now())
	if !ok {
		return api.EscalationView{}, errors.New("escalation not found or already acknowledged")
	}
	g.approval.RecordAudit(context.Background(), actor, "approver", "gate.escalation.ack", "gate_notification",
		notificationID, note)
	return api.EscalationView{
		NotificationID: rec.NotificationID, Severity: severity, CreatedAt: createdAt, Level: level,
		Acked: true, AckedBy: actor, AckedAt: rec.At,
	}, nil
}
