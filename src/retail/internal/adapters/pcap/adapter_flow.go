// Flow/asset aggregation for the PCAP adapter.
package pcap

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/collect"
	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/netx"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
)

// flowAgg accumulates one conversation.
type flowAgg struct {
	srcIP    string
	dstIP    string
	srcPort  int
	dstPort  int
	protocol string
	bytes    int64
	packets  int64
	last     time.Time
}

// assetAgg accumulates one observed IP.
type assetAgg struct {
	ip        string
	protocols map[string]struct{}
	bytes     int64
	packets   int64
	last      time.Time
}

// observePacket feeds the packet into the flow and asset aggregation. It is
// called for every decoded packet, including non-IP frames (ignored here).
func (d *dispatcher) observePacket(pkt Packet) {
	if pkt.SrcIP == "" || pkt.DstIP == "" {
		return
	}
	proto := flowProtocol(pkt)
	d.addFlow(pkt, proto)
	d.addAsset(pkt, proto)
}

// flowProtocol labels a flow. Ports are hints, never proof.
func flowProtocol(pkt Packet) string {
	switch pkt.Protocol {
	case ipProtoTCP:
		if label := serviceLabel(pkt.SrcPort); label != "" && isServerPort(pkt.SrcPort) {
			return label
		}
		if label := serviceLabel(pkt.DstPort); label != "" {
			return label
		}
		return "tcp"
	case ipProtoUDP:
		if label := serviceLabel(pkt.DstPort); label != "" {
			return label
		}
		if label := serviceLabel(pkt.SrcPort); label != "" {
			return label
		}
		return "udp"
	case ipProtoICMP:
		return "icmp"
	default:
		return "ip"
	}
}

func serviceLabel(port uint16) string { return netx.ServiceProtocol(int(port)) }

// isServerPort reports whether the port belongs to a known service port set.
func isServerPort(port uint16) bool {
	switch port {
	case 502, 47808, 1883, 8883, 161, 162, 80, 443, 8000, 8080, 8443:
		return true
	}
	return false
}

func (d *dispatcher) addFlow(pkt Packet, protocol string) {
	flow := netx.Flow{
		SrcIP:    pkt.SrcIP,
		DstIP:    pkt.DstIP,
		SrcPort:  int(pkt.SrcPort),
		DstPort:  int(pkt.DstPort),
		Protocol: protocol,
	}
	if err := flow.Validate(); err != nil {
		return
	}
	key := flow.Key()
	agg, ok := d.flows[key]
	if !ok {
		canonical := flow.Canonical()
		agg = &flowAgg{
			srcIP:    canonical.SrcIP,
			dstIP:    canonical.DstIP,
			srcPort:  canonical.SrcPort,
			dstPort:  canonical.DstPort,
			protocol: protocol,
		}
		d.flows[key] = agg
	}
	size := int64(pkt.Bytes)
	if size <= 0 {
		size = int64(len(pkt.Payload))
	}
	agg.bytes += size
	agg.packets++
	agg.last = pkt.Timestamp
}

func (d *dispatcher) addAsset(pkt Packet, protocol string) {
	for _, ip := range []string{pkt.SrcIP, pkt.DstIP} {
		agg, ok := d.assets[ip]
		if !ok {
			agg = &assetAgg{ip: ip, protocols: make(map[string]struct{}, 2)}
			d.assets[ip] = agg
		}
		agg.protocols[protocol] = struct{}{}
		size := int64(pkt.Bytes)
		if size <= 0 {
			size = int64(len(pkt.Payload))
		}
		agg.bytes += size
		agg.packets++
		agg.last = pkt.Timestamp
	}
}

// flushFlows emits the aggregated conversations deterministically (sorted by
// key). The counters are reset afterwards.
func (d *dispatcher) flushFlows(ctx context.Context, sink ports.Sink) error {
	if len(d.flows) == 0 {
		return nil
	}
	keys := make([]string, 0, len(d.flows))
	for key := range d.flows {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	events := make([]domain.Event, 0, len(keys))
	for _, key := range keys {
		agg := d.flows[key]
		observed := agg.last
		if observed.IsZero() {
			observed = d.meta.Now()
		}
		flow := domain.FlowMeta{
			SrcIP:     agg.srcIP,
			DstIP:     agg.dstIP,
			SrcPort:   agg.srcPort,
			DstPort:   agg.dstPort,
			Protocol:  agg.protocol,
			Bytes:     agg.bytes,
			Packets:   agg.packets,
			Direction: "internal",
		}
		ev, err := d.meta.FlowEvent(flow, 0.55, observed)
		if err != nil {
			d.counters.IncError(err.Error())
			continue
		}
		events = append(events, ev)
	}
	d.flows = make(map[string]*flowAgg)
	if err := collect.EmitAll(ctx, sink, events); err != nil {
		d.counters.IncError(err.Error())
		return err
	}
	return nil
}

// flushAssets emits one asset hypothesis per observed IP. It never invents a
// vendor/model: only the IP and the observed protocol hints are reported.
func (d *dispatcher) flushAssets(ctx context.Context, sink ports.Sink) error {
	if len(d.assets) == 0 {
		return nil
	}
	ips := make([]string, 0, len(d.assets))
	for ip := range d.assets {
		ips = append(ips, ip)
	}
	sort.Slice(ips, func(i, j int) bool {
		return netx.CompareEndpoints(ips[i], 0, ips[j], 0) < 0
	})
	events := make([]domain.Event, 0, len(ips))
	for _, ip := range ips {
		agg := d.assets[ip]
		protocols := make([]string, 0, len(agg.protocols))
		for protocol := range agg.protocols {
			protocols = append(protocols, protocol)
		}
		sort.Strings(protocols)
		observed := agg.last
		if observed.IsZero() {
			observed = d.meta.Now()
		}
		dev := domain.DeviceMeta{IP: ip}
		ev, err := d.meta.AssetSeenEvent(dev, 0.4, observed)
		if err != nil {
			d.counters.IncError(err.Error())
			continue
		}
		ev.PayloadMeta = map[string]string{
			"protocols": strings.Join(protocols, ","),
			"packets":   strconv.FormatInt(agg.packets, 10),
		}
		events = append(events, ev)
	}
	d.assets = make(map[string]*assetAgg)
	if err := collect.EmitAll(ctx, sink, events); err != nil {
		d.counters.IncError(err.Error())
		return err
	}
	return nil
}

// resetTimestamp returns the observed packet time or the meta clock.
func (d *dispatcher) observedOrNow(at time.Time) time.Time {
	if at.IsZero() {
		return d.meta.Now()
	}
	return at
}
