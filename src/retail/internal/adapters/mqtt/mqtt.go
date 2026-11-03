// Package mqtt implements the read-only MQTT 3.1.1 collector.
//
// The client speaks the minimum needed to receive telemetry:
// CONNECT, SUBSCRIBE (QoS 0), PINGREQ/PINGRESP, inbound PUBLISH and DISCONNECT.
// There is intentionally no encoder for PUBLISH: the adapter cannot publish to
// a device or broker (safety invariant S-01). Reconnects use exponential
// backoff with jitter; wildcard subscriptions must be enabled explicitly
// because '#' subscriptions are a known data-flood risk.
//
// Credentials are read from the operator configuration and are never logged,
// never put into events and never returned by Health().
package mqtt

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/collect"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
)

const adapterVersion = "1"

// Option keys owned by the adapter.
const (
	optBroker        = "broker"
	optTopics        = "topics"
	optSensors       = "sensors"
	optClientID      = "client_id"
	optUsername      = "username"
	optPassword      = "password"
	optKeepalive     = "keepalive"
	optTimeout       = "timeout"
	optAllowWildcard = "allow_wildcard"
)

const (
	defaultClientID  = "gedefense-retail"
	defaultKeepalive = 30 * time.Second
	defaultTimeout   = 5 * time.Second
	minKeepalive     = 5 * time.Second
	maxKeepalive     = 600 * time.Second
	minTimeout       = time.Second
	maxClientIDLen   = 128
)

// ErrNoTopicMapping is returned when neither topics nor sensor mappings exist.
var ErrNoTopicMapping = errors.New("mqtt: option topics or sensors is required")

// Adapter is the read-only MQTT collector.
type Adapter struct {
	cfg       collect.AdapterConfig
	meta      collect.Meta
	broker    string
	clientID  string
	username  string
	password  string
	keepalive time.Duration
	timeout   time.Duration
	topics    []string
	mappings  []TopicMapping
	counters  collect.Counters
}

// New creates the adapter and validates every option before a connection is
// attempted.
func New(cfg collect.AdapterConfig) (ports.Collector, error) {
	site, err := cfg.ResolveSite()
	if err != nil {
		return nil, err
	}
	a := &Adapter{
		cfg:       cfg,
		broker:    cfg.Option(optBroker),
		clientID:  cfg.Option(optClientID),
		username:  cfg.Option(optUsername),
		password:  cfg.Option(optPassword),
		keepalive: defaultKeepalive,
		timeout:   defaultTimeout,
	}
	if a.broker == "" {
		return nil, fmt.Errorf("mqtt %q: option %s is required", cfg.AdapterID, optBroker)
	}
	if _, _, err := net.SplitHostPort(a.broker); err != nil {
		return nil, fmt.Errorf("mqtt %q: option %s %q: %w", cfg.AdapterID, optBroker, a.broker, err)
	}
	if a.clientID == "" {
		a.clientID = defaultClientID
	}
	if err := validateUTF8String(a.clientID, maxClientIDLen); err != nil {
		return nil, fmt.Errorf("mqtt %q: option %s: %w", cfg.AdapterID, optClientID, err)
	}
	if err := validateUTF8String(a.username, 128); err != nil {
		return nil, fmt.Errorf("mqtt %q: option %s: %w", cfg.AdapterID, optUsername, err)
	}
	if len(a.password) > 256 {
		return nil, fmt.Errorf("mqtt %q: option %s is too long", cfg.AdapterID, optPassword)
	}
	if raw := cfg.Option(optKeepalive); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil || d < minKeepalive || d > maxKeepalive {
			return nil, fmt.Errorf("mqtt %q: option %s must be %s..%s", cfg.AdapterID, optKeepalive, minKeepalive, maxKeepalive)
		}
		a.keepalive = d
	}
	if raw := cfg.Option(optTimeout); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil || d < minTimeout || d > time.Minute {
			return nil, fmt.Errorf("mqtt %q: option %s must be %s..1m", cfg.AdapterID, optTimeout, minTimeout)
		}
		a.timeout = d
	}
	allowWildcard := cfg.Option(optAllowWildcard) == "1" || cfg.Option(optAllowWildcard) == "true"

	mappings, err := ParseTopicMappings(cfg.Option(optSensors))
	if err != nil {
		return nil, fmt.Errorf("mqtt %q: %w", cfg.AdapterID, err)
	}
	a.mappings = mappings

	topics := splitList(cfg.Option(optTopics))
	if len(topics) == 0 {
		for _, m := range mappings {
			topics = append(topics, m.Filter)
		}
	}
	if len(topics) == 0 {
		return nil, fmt.Errorf("mqtt %q: %w", cfg.AdapterID, ErrNoTopicMapping)
	}
	for _, topic := range topics {
		if err := validateTopicFilter(topic, allowWildcard); err != nil {
			return nil, fmt.Errorf("mqtt %q: topic %q: %w", cfg.AdapterID, topic, err)
		}
	}
	a.topics = dedupe(topics)

	a.meta = collect.Meta{
		SiteID:     site,
		ZoneID:     cfg.ZoneID,
		Source:     cfg.AdapterID,
		Collection: collect.CollectionPassiveTap,
		Protocol:   "mqtt",
		Clock:      cfg.Clock,
	}
	if err := a.meta.Validate(); err != nil {
		return nil, fmt.Errorf("mqtt %q: %w", cfg.AdapterID, err)
	}
	return a, nil
}

// Info implements ports.Collector.
func (a *Adapter) Info() ports.Info {
	return ports.Info{
		AdapterID:   a.cfg.AdapterID,
		Version:     adapterVersion,
		Protocols:   []string{"mqtt"},
		Collection:  collect.CollectionPassiveTap,
		ReadOnly:    true,
		Description: "Read-only MQTT 3.1.1 subscriber (CONNECT/SUBSCRIBE QoS0/PINGREQ, inbound PUBLISH only); no publish path exists.",
	}
}

// Start implements ports.Collector. It blocks until ctx is cancelled.
func (a *Adapter) Start(ctx context.Context, sink ports.Sink) error {
	if ctx == nil {
		return errors.New("mqtt: nil context")
	}
	if sink == nil {
		return errors.New("mqtt: nil sink")
	}
	backoff := collect.NewBackoff(collect.DefaultBackoffBase, collect.DefaultBackoffMax)
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		err := a.session(ctx, sink)
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			a.counters.IncError(fmt.Sprintf("session: %v", err))
		}
		select {
		case <-time.After(backoff.Next()):
		case <-ctx.Done():
			return nil
		}
	}
}

// HealthCounters implements collect.Instrumented.
func (a *Adapter) HealthCounters() collect.CounterSnapshot { return a.counters.HealthCounters() }

// HealthState exposes the read-only/degraded contract of the adapter.
func (a *Adapter) HealthState() (string, string) {
	return "running", ""
}

func (a *Adapter) now() time.Time {
	if a.cfg.Clock != nil {
		return a.cfg.Clock.Now().UTC()
	}
	return time.Now().UTC()
}

func splitList(value string) []string {
	out := make([]string, 0, 4)
	current := make([]byte, 0, 64)
	flush := func() {
		if s := string(current); s != "" {
			out = append(out, s)
		}
		current = current[:0]
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c == ',' || c == ';' || c == '\n' {
			flush()
			continue
		}
		if c == ' ' || c == '\t' || c == '\r' {
			continue
		}
		current = append(current, c)
	}
	flush()
	return out
}

func dedupe(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
