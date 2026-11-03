// Package bypass implements the pure logic of "Bypass vermutet": a passive
// write observation on a device that did not come over the Gate data path.
//
// Alpha boundary (lead decision): the 0.1 packages — including the passive
// `retail.write-attempt` rule in retaild — are NOT changed in this release.
// retaild already raises the 0.1 alert; this package contains the reusable gate
// logic and its tests. At integration time (G2) retaild maps its passive write
// event onto a PassiveWriteSignal and calls Observe; no fake bridge and no claim
// of an already wired pipeline is made here.
//
// Documented limit: passive observation can prove that a write attempt was seen
// on the wire and that its source is not the configured gate source. It cannot
// prove who initiated it, whether it was authorized, or that a segmentation
// bypass exists. The alert says exactly that.
package bypass

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/alert"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
)

// PassiveWriteSignal is one injected passive write observation. It is
// intentionally decoupled from the 0.1 event type: the integration layer (G2)
// maps `domain.Event{Kind: EventWriteAttempt}` onto it, which keeps the alpha
// free of API changes.
type PassiveWriteSignal struct {
	SiteID    domain.SiteID
	At        time.Time
	SourceIP  string
	Target    string // observed device address/identifier (evidence only)
	TargetID  domain.TargetID
	AssetID   domain.AssetID
	Protocol  string
	Function  string
	Address   string
	ValueHint string
	Allowed   bool // passive adapter's own allowlist verdict (unproven)
	Detail    string
}

// Emitter receives the finished gate alert (the alert.Engine satisfies it).
type Emitter interface {
	Emit(ctx context.Context, a alert.Alert) (alert.Alert, error)
}

// Options configures the bypass detector.
type Options struct {
	Clock   ports.Clock
	Emitter Emitter
	// GateCIDRs are the addresses/CIDRs from which Gate writes are expected.
	// A write from one of them is not a bypass (it may still be an unauthorized
	// write, which the Gate itself decides and audits).
	GateCIDRs []string
}

// Engine evaluates passive write signals and emits critical bypass alerts.
type Engine struct {
	clock       ports.Clock
	emitter     Emitter
	gateNets    []*net.IPNet
	gateSources []string
}

// New validates the configuration and parses the gate source ranges.
func New(opts Options) (*Engine, error) {
	if opts.Clock == nil {
		return nil, errors.New("bypass: clock is required")
	}
	if opts.Emitter == nil {
		return nil, errors.New("bypass: emitter is required")
	}
	if len(opts.GateCIDRs) == 0 {
		return nil, errors.New("bypass: at least one gate source CIDR is required")
	}
	engine := &Engine{clock: opts.Clock, emitter: opts.Emitter}
	for _, raw := range opts.GateCIDRs {
		network, err := parseGateSource(raw)
		if err != nil {
			return nil, err
		}
		engine.gateNets = append(engine.gateNets, network)
		engine.gateSources = append(engine.gateSources, network.String())
	}
	return engine, nil
}

// Observe evaluates one passive write signal. It returns the emitted alert and
// whether a bypass suspicion was raised. A write from a configured gate source
// is not reported by this package (the Gate's own audit/deny path owns it).
func (e *Engine) Observe(ctx context.Context, signal PassiveWriteSignal) (alert.Alert, bool, error) {
	if e == nil {
		return alert.Alert{}, false, errors.New("bypass: nil engine")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return alert.Alert{}, false, err
	}
	if signal.At.IsZero() {
		return alert.Alert{}, false, errors.New("bypass: signal requires at")
	}
	source := strings.TrimSpace(signal.SourceIP)
	if source == "" {
		return alert.Alert{}, false, errors.New("bypass: signal requires a source ip")
	}
	at := signal.At.UTC()
	if at.After(e.clock.Now().UTC()) {
		at = e.clock.Now().UTC()
	}
	site := signal.SiteID

	ip := net.ParseIP(source)
	if ip != nil && e.isGateSource(ip) {
		return alert.Alert{}, false, nil
	}
	details := alert.BypassDetails{
		SiteID:         site,
		At:             at,
		TargetID:       signal.TargetID,
		AssetID:        signal.AssetID,
		SourceIP:       source,
		Protocol:       signal.Protocol,
		Function:       signal.Function,
		Address:        signal.Address,
		ValueHint:      signal.ValueHint,
		ObservedTarget: signal.Target,
		Allowed:        signal.Allowed,
		Detail:         signal.Detail,
		Confidence:     0.70,
	}
	if ip == nil {
		// The source cannot be attributed at all: the observation is still a
		// bypass suspicion, but with lower confidence and an explicit note.
		details.Confidence = 0.6
		details.Detail = joinDetail(details.Detail, "Quell-IP ist nicht parsebar; Gate-Zuordnung nicht möglich.")
	} else if !e.isGateSource(ip) {
		details.GateSources = append([]string(nil), e.gateSources...)
	}
	if signal.Target == "" && signal.TargetID != "" {
		details.ObservedTarget = string(signal.TargetID)
	}
	emitted, err := e.emitter.Emit(ctx, alert.NewBypassAlert(details))
	if err != nil {
		return emitted, false, fmt.Errorf("bypass: emit alert: %w", err)
	}
	return emitted, true, nil
}

func (e *Engine) isGateSource(ip net.IP) bool {
	for _, network := range e.gateNets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func parseGateSource(raw string) (*net.IPNet, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("bypass: empty gate source")
	}
	if strings.Contains(raw, "/") {
		_, network, err := net.ParseCIDR(raw)
		if err != nil {
			return nil, fmt.Errorf("bypass: invalid gate CIDR %q: %w", raw, err)
		}
		return network, nil
	}
	ip := net.ParseIP(raw)
	if ip == nil {
		return nil, fmt.Errorf("bypass: invalid gate source %q", raw)
	}
	if ip.To4() != nil {
		return &net.IPNet{IP: ip.To4(), Mask: net.CIDRMask(32, 32)}, nil
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}, nil
}

func joinDetail(existing, extra string) string {
	existing = strings.TrimSpace(existing)
	if existing == "" {
		return extra
	}
	return existing + " " + extra
}
