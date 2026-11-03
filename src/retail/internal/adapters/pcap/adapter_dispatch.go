// Packet dispatch into the protocol decoders.
package pcap

import (
	"context"
	"fmt"
	"strconv"

	"github.com/visiongaiatechnology/gedefense/retail/internal/adapters/bacnet"
	"github.com/visiongaiatechnology/gedefense/retail/internal/adapters/httpui"
	"github.com/visiongaiatechnology/gedefense/retail/internal/adapters/modbus"
	"github.com/visiongaiatechnology/gedefense/retail/internal/adapters/mqtt"
	"github.com/visiongaiatechnology/gedefense/retail/internal/collect"
	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/netx"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
)

// dispatchConfig carries the decoder mappings shared by every connection.
type dispatchConfig struct {
	Meta           collect.Meta
	ModbusRegs     []modbus.RegisterSpec
	MQTTMappings   []mqtt.TopicMapping
	BacnetMappings []bacnet.ObjectMapping
	HTTPPorts      map[uint16]bool
}

// connDecoders holds the per-connection passive decoders.
type connDecoders struct {
	serverIP   string
	serverPort uint16
	clientIP   string
	clientPort uint16
	modbus     *modbus.Tap
	mqtt       *mqtt.StreamDecoder
	http       *httpui.Decoder
}

// dispatcher owns the aggregation state and the decoders for one adapter run.
type dispatcher struct {
	cfg           dispatchConfig
	meta          collect.Meta
	counters      collect.Counters
	flows         map[string]*flowAgg
	assets        map[string]*assetAgg
	conns         map[string]*connDecoders
	bacnetDecoder *bacnet.Decoder
}

const maxTrackedConnections = 1024

// newDispatcher builds the dispatcher and its stateless decoders.
func newDispatcher(cfg dispatchConfig) (*dispatcher, error) {
	d := &dispatcher{
		cfg:    cfg,
		meta:   cfg.Meta,
		flows:  make(map[string]*flowAgg),
		assets: make(map[string]*assetAgg),
		conns:  make(map[string]*connDecoders),
	}
	decoder, err := bacnet.NewDecoder(bacnet.DecoderOptions{Meta: cfg.Meta, Mappings: cfg.BacnetMappings})
	if err != nil {
		return nil, fmt.Errorf("pcap: bacnet decoder: %w", err)
	}
	d.bacnetDecoder = decoder
	return d, nil
}

// handle routes one decoded packet to the matching decoders and aggregation.
func (d *dispatcher) handle(ctx context.Context, sink ports.Sink, pkt Packet) error {
	var events []domain.Event
	switch pkt.Protocol {
	case ipProtoTCP:
		if len(pkt.Payload) > 0 {
			events = d.handleTCP(pkt)
		}
	case ipProtoUDP:
		events = d.handleUDP(pkt)
	}
	d.observePacket(pkt)
	if len(events) == 0 {
		return nil
	}
	if err := collect.EmitAll(ctx, sink, events); err != nil {
		d.counters.IncError(err.Error())
		return err
	}
	return nil
}

func (d *dispatcher) handleTCP(pkt Packet) []domain.Event {
	serverIP, serverPort, clientIP, clientPort, ok := tcpServerSide(pkt)
	if !ok {
		return nil
	}
	key := connKey(serverIP, serverPort, clientIP, clientPort)
	conn, exists := d.conns[key]
	if !exists {
		if len(d.conns) >= maxTrackedConnections {
			d.conns = make(map[string]*connDecoders)
			d.counters.IncError("connection tracking table reset")
		}
		conn = &connDecoders{
			serverIP:   serverIP,
			serverPort: serverPort,
			clientIP:   clientIP,
			clientPort: clientPort,
		}
		switch {
		case serverPort == 502:
			tap, err := modbus.NewTap(modbus.TapOptions{
				Meta:      d.cfg.Meta,
				Registers: d.cfg.ModbusRegs,
				DeviceIP:  serverIP,
				Peer:      netx.FormatEndpoint(clientIP, clientPort),
			})
			if err != nil {
				d.counters.IncError(err.Error())
				return nil
			}
			conn.modbus = tap
		case serverPort == 1883 || serverPort == 8883:
			decoder, err := mqtt.NewStreamDecoder(mqtt.StreamOptions{
				Meta:     d.cfg.Meta,
				Mappings: d.cfg.MQTTMappings,
			})
			if err != nil {
				d.counters.IncError(err.Error())
				return nil
			}
			conn.mqtt = decoder
		case d.cfg.HTTPPorts[serverPort] || defaultHTTPPort(serverPort):
			decoder, err := httpui.NewDecoder(httpui.DecoderOptions{Meta: d.cfg.Meta})
			if err != nil {
				d.counters.IncError(err.Error())
				return nil
			}
			conn.http = decoder
		}
		d.conns[key] = conn
	}

	dir := modbus.DirectionToServer
	if pkt.SrcPort == serverPort && pkt.SrcIP == serverIP {
		dir = modbus.DirectionToClient
	}
	switch {
	case conn.modbus != nil:
		return conn.modbus.Feed(pkt.Payload, dir)
	case conn.mqtt != nil:
		return conn.mqtt.Feed(pkt.Payload)
	case conn.http != nil:
		meta := httpui.ConnMeta{
			ClientIP:   clientIP,
			ClientPort: clientPort,
			ServerIP:   serverIP,
			ServerPort: serverPort,
		}
		return conn.http.Feed(meta, pkt.Payload)
	default:
		return nil
	}
}

func (d *dispatcher) handleUDP(pkt Packet) []domain.Event {
	var remoteIP string
	switch {
	case pkt.SrcPort == 47808:
		remoteIP = pkt.SrcIP
	case pkt.DstPort == 47808:
		remoteIP = pkt.DstIP
	default:
		return nil
	}
	return d.bacnetDecoder.Feed(remoteIP, pkt.Payload)
}

// tcpServerSide identifies the server endpoint. Ports are hints: the known
// service port wins, otherwise no L7 decoding is attempted.
func tcpServerSide(pkt Packet) (serverIP string, serverPort uint16, clientIP string, clientPort uint16, ok bool) {
	switch {
	case isServerPort(pkt.DstPort):
		return pkt.DstIP, pkt.DstPort, pkt.SrcIP, pkt.SrcPort, true
	case isServerPort(pkt.SrcPort):
		return pkt.SrcIP, pkt.SrcPort, pkt.DstIP, pkt.DstPort, true
	default:
		return "", 0, "", 0, false
	}
}

func connKey(serverIP string, serverPort uint16, clientIP string, clientPort uint16) string {
	return serverIP + ":" + strconv.Itoa(int(serverPort)) + "<-" + clientIP + ":" + strconv.Itoa(int(clientPort))
}

func defaultHTTPPort(port uint16) bool {
	switch port {
	case 80, 8000, 8080, 443, 8443:
		return true
	}
	return false
}

// flush emits aggregated flows and assets, then merges the decoder counters.
func (d *dispatcher) flush(ctx context.Context, sink ports.Sink) error {
	if err := d.flushFlows(ctx, sink); err != nil {
		return err
	}
	if err := d.flushAssets(ctx, sink); err != nil {
		return err
	}
	d.counters.Merge(d.bacnetDecoder.HealthCounters())
	for _, conn := range d.conns {
		if conn.modbus != nil {
			d.counters.Merge(conn.modbus.HealthCounters())
		}
		if conn.mqtt != nil {
			d.counters.Merge(conn.mqtt.HealthCounters())
		}
		if conn.http != nil {
			d.counters.Merge(conn.http.HealthCounters())
		}
	}
	return nil
}

// HealthCounters exposes the merged decoder counters.
func (d *dispatcher) HealthCounters() collect.CounterSnapshot { return d.counters.HealthCounters() }
