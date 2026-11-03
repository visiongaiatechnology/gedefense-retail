// Package bacnet implements the passive BACnet/IP decoder.
//
// The collector only reads datagrams from a local UDP feed (or receives
// payloads from the PCAP adapter). It never sends Who-Is, ReadProperty or
// WriteProperty: there is no socket write path in this package at all
// (enforced by internal/adapters/safety_test.go).
//
// Decoded: I-Am (device instance, vendor id) and ReadProperty-ACK for
// AnalogInput, AnalogValue, BinaryInput and BinaryValue. Observed
// WriteProperty/WritePropertyMultiple confirmed requests are reported as
// domain.EventWriteAttempt, never executed.
package bacnet

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/collect"
	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/netx"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
)

const adapterVersion = "1"

// Option keys owned by the adapter.
const (
	optListen       = "listen"
	optObjects      = "objects"
	optFlowInterval = "flow_interval"
)

const (
	defaultFlowInterval = 60 * time.Second
	maxDatagramBytes    = 2048
	readDeadline        = 500 * time.Millisecond
)

// ErrNoFeed is returned when the adapter has no UDP feed listener.
var ErrNoFeed = errors.New("bacnet: option listen is required (no active polling in the MVP)")

// peerStat accumulates one peer's traffic between flow flushes.
type peerStat struct {
	packets int64
	bytes   int64
}

// Adapter is the passive BACnet/IP collector.
type Adapter struct {
	cfg          collect.AdapterConfig
	listen       string
	meta         collect.Meta
	decoder      *Decoder
	flowInterval time.Duration
	counters     collect.Counters
}

// New creates the adapter. Only passive feed mode exists.
func New(cfg collect.AdapterConfig) (ports.Collector, error) {
	site, err := cfg.ResolveSite()
	if err != nil {
		return nil, err
	}
	a := &Adapter{
		cfg:          cfg,
		listen:       cfg.Option(optListen),
		flowInterval: defaultFlowInterval,
	}
	if a.listen == "" {
		return nil, fmt.Errorf("bacnet %q: %w", cfg.AdapterID, ErrNoFeed)
	}
	if _, _, err := net.SplitHostPort(a.listen); err != nil {
		return nil, fmt.Errorf("bacnet %q: option %s %q: %w", cfg.AdapterID, optListen, a.listen, err)
	}
	if raw := cfg.Option(optFlowInterval); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil || d < time.Second {
			return nil, fmt.Errorf("bacnet %q: option %s must be a duration >= 1s", cfg.AdapterID, optFlowInterval)
		}
		a.flowInterval = d
	}
	mappings, err := ParseObjectMappings(cfg.Option(optObjects))
	if err != nil {
		return nil, fmt.Errorf("bacnet %q: %w", cfg.AdapterID, err)
	}
	a.meta = collect.Meta{
		SiteID:     site,
		ZoneID:     cfg.ZoneID,
		Source:     cfg.AdapterID,
		Collection: collect.CollectionPassiveTap,
		Protocol:   "bacnet_ip",
		Clock:      cfg.Clock,
	}
	if err := a.meta.Validate(); err != nil {
		return nil, fmt.Errorf("bacnet %q: %w", cfg.AdapterID, err)
	}
	a.decoder, err = NewDecoder(DecoderOptions{Meta: a.meta, Mappings: mappings})
	if err != nil {
		return nil, fmt.Errorf("bacnet %q: %w", cfg.AdapterID, err)
	}
	return a, nil
}

// Info implements ports.Collector.
func (a *Adapter) Info() ports.Info {
	return ports.Info{
		AdapterID:   a.cfg.AdapterID,
		Version:     adapterVersion,
		Protocols:   []string{"bacnet_ip"},
		Collection:  collect.CollectionPassiveTap,
		ReadOnly:    true,
		Description: "Passive BACnet/IP decoder (I-Am, ReadProperty-ACK AI/AV/BI/BV); no Who-Is, no ReadProperty, no WriteProperty is ever sent.",
	}
}

// Start implements ports.Collector. It blocks until ctx is cancelled.
func (a *Adapter) Start(ctx context.Context, sink ports.Sink) error {
	if ctx == nil {
		return errors.New("bacnet: nil context")
	}
	if sink == nil {
		return errors.New("bacnet: nil sink")
	}
	var lc net.ListenConfig
	conn, err := lc.ListenPacket(ctx, "udp", a.listen)
	if err != nil {
		return fmt.Errorf("bacnet %q: listen %q: %w", a.cfg.AdapterID, a.listen, err)
	}
	defer func() { _ = conn.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()

	peers := make(map[string]*peerStat)
	seenPeer := make(map[string]bool)
	flowTicker := time.NewTicker(a.flowInterval)
	defer flowTicker.Stop()

	buf := make([]byte, maxDatagramBytes)
	for {
		select {
		case <-ctx.Done():
			a.flushFlows(ctx, sink, peers)
			return nil
		case <-flowTicker.C:
			a.flushFlows(ctx, sink, peers)
			continue
		default:
		}
		if err := conn.SetReadDeadline(time.Now().Add(readDeadline)); err != nil {
			return err
		}
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				a.flushFlows(ctx, sink, peers)
				return nil
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			a.counters.IncError(fmt.Sprintf("read: %v", err))
			continue
		}
		remoteIP := addrIP(addr)
		events := a.decoder.Feed(remoteIP, buf[:n])
		stat, ok := peers[remoteIP]
		if !ok {
			stat = &peerStat{}
			peers[remoteIP] = stat
		}
		stat.packets++
		stat.bytes += int64(n)
		if !seenPeer[remoteIP] && remoteIP != "" {
			seenPeer[remoteIP] = true
			if ev, err := a.meta.AssetSeenEvent(domain.DeviceMeta{IP: remoteIP}, 0.4, a.now()); err == nil {
				events = append(events, ev)
			}
		}
		if len(events) > 0 {
			if err := collect.EmitAll(ctx, sink, events); err != nil {
				a.counters.IncError(err.Error())
			}
		}
	}
}

func (a *Adapter) flushFlows(ctx context.Context, sink ports.Sink, peers map[string]*peerStat) {
	if len(peers) == 0 || ctx.Err() != nil {
		return
	}
	localIP := a.listenHost()
	now := a.now()
	events := make([]domain.Event, 0, len(peers))
	for remote, stat := range peers {
		flow := domain.FlowMeta{
			SrcIP:     remote,
			DstIP:     localIP,
			SrcPort:   47808,
			DstPort:   47808,
			Protocol:  "bacnet_ip",
			Bytes:     stat.bytes,
			Packets:   stat.packets,
			Direction: "internal",
		}
		ev, err := a.meta.FlowEvent(flow, 0.5, now)
		if err != nil {
			continue
		}
		events = append(events, ev)
		stat.packets = 0
		stat.bytes = 0
	}
	if err := collect.EmitAll(ctx, sink, events); err != nil {
		a.counters.IncError(err.Error())
	}
}

func (a *Adapter) listenHost() string {
	host, _, err := net.SplitHostPort(a.listen)
	if err != nil {
		return a.listen
	}
	return host
}

func (a *Adapter) now() time.Time {
	if a.cfg.Clock != nil {
		return a.cfg.Clock.Now().UTC()
	}
	return time.Now().UTC()
}

// HealthCounters merges the decoder counters into the adapter counters.
func (a *Adapter) HealthCounters() collect.CounterSnapshot {
	return a.counters.HealthCounters().Merge(a.decoder.HealthCounters())
}

func addrIP(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return ""
	}
	if _, err := netx.ParseAddr(host); err != nil {
		return ""
	}
	return host
}
