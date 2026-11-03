// Strictly read-only poll mode (FC3/FC4 only).
package modbus

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sort"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/collect"
	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
)

// pollGroup is one minimal read request: consecutive registers of one function
// code. Grouping keeps the request count (and the plant load) low.
type pollGroup struct {
	function uint8
	start    uint16
	specs    []RegisterSpec
}

// buildPollGroups sorts the specs and merges consecutive addresses into
// requests of at most maxPollQuantity registers.
func buildPollGroups(specs []RegisterSpec) []pollGroup {
	sorted := make([]RegisterSpec, len(specs))
	copy(sorted, specs)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Function != sorted[j].Function {
			return sorted[i].Function < sorted[j].Function
		}
		return sorted[i].Address < sorted[j].Address
	})
	groups := make([]pollGroup, 0, len(sorted))
	for _, spec := range sorted {
		if n := len(groups); n > 0 {
			last := &groups[n-1]
			end := last.start + uint16(len(last.specs))
			if last.function == spec.Function && spec.Address == end && len(last.specs) < maxPollQuantity {
				last.specs = append(last.specs, spec)
				continue
			}
		}
		groups = append(groups, pollGroup{function: spec.Function, start: spec.Address, specs: []RegisterSpec{spec}})
	}
	return groups
}

// pollRequest is one encoded read request plus its expected response shape.
type pollRequest struct {
	group         pollGroup
	transactionID uint16
}

// runPoll connects, polls the approved registers and reconnects with backoff.
// The polling itself is the only active read in the product and it is limited
// to FC3/FC4 by the register specification gate.
func (a *Adapter) runPoll(ctx context.Context, sink ports.Sink) error {
	backoff := collect.NewBackoff(collect.DefaultBackoffBase, collect.DefaultBackoffMax)
	flowTicker := time.NewTicker(a.flowInterval)
	defer flowTicker.Stop()
	pollTimer := time.NewTimer(0)
	defer pollTimer.Stop()

	var conn net.Conn
	var txID uint16
	var flow flowStats
	defer func() {
		if conn != nil {
			_ = conn.Close()
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-flowTicker.C:
			a.emitPollFlow(ctx, sink, &flow, conn)
			continue
		case <-pollTimer.C:
		}

		if conn == nil {
			c, err := a.dial(ctx)
			if err != nil {
				a.counters.IncError(fmt.Sprintf("dial %s: %v", a.target, err))
				select {
				case <-time.After(backoff.Next()):
					continue
				case <-ctx.Done():
					return nil
				}
			}
			conn = c
			backoff.Reset()
			a.emitPollAssetSeen(ctx, sink)
		}

		stats, err := a.pollOnce(ctx, conn, sink, &txID)
		flow.merge(stats)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			a.counters.IncError(fmt.Sprintf("poll %s: %v", a.target, err))
			_ = conn.Close()
			conn = nil
			continue
		}
		pollTimer.Reset(a.nextInterval())
	}
}

// nextInterval adds mild jitter so that multiple gateways do not synchronize
// their polls; the base interval is operator-configured.
func (a *Adapter) nextInterval() time.Duration {
	span := int64(a.interval / 20) // up to 5%
	if span <= 0 {
		return a.interval
	}
	return a.interval + time.Duration(time.Now().UnixNano()%span)
}

func (a *Adapter) dial(ctx context.Context) (net.Conn, error) {
	dialer := net.Dialer{Timeout: a.timeout}
	conn, err := dialer.DialContext(ctx, "tcp", a.target)
	if err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(time.Now().Add(a.timeout)); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

// pollOnce performs one request/response round trip per register group.
func (a *Adapter) pollOnce(ctx context.Context, conn net.Conn, sink ports.Sink, txID *uint16) (flowStats, error) {
	stats := flowStats{}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()
	for _, group := range a.pollGroups {
		*txID = *txID + 1
		request := encodeReadRequest(*txID, a.unit, group.function, group.start, uint16(len(group.specs)))
		if err := conn.SetDeadline(time.Now().Add(a.timeout)); err != nil {
			return stats, err
		}
		if _, err := conn.Write(request); err != nil {
			return stats, fmt.Errorf("write request: %w", err)
		}
		stats.sentBytes += int64(len(request))
		stats.sentPackets++

		values, err := readResponse(conn, *txID, group.function)
		if err != nil {
			return stats, err
		}
		stats.recvBytes += int64(7 + 2 + 2*len(values))
		stats.recvPackets++

		now := a.now()
		for i, spec := range group.specs {
			if i >= len(values) {
				break
			}
			meas := domain.Measurement{
				Value:      scaleRaw(values[i], spec),
				Unit:       spec.Unit,
				Quality:    domain.QualityGood,
				Metric:     spec.Metric,
				ObservedAt: now,
			}
			ev, err := a.meta.TelemetryEvent(spec.SensorID, spec.AssetID, meas, 0.9, now)
			if err != nil {
				a.counters.IncError(err.Error())
				continue
			}
			if err := collect.EmitAll(ctx, sink, []domain.Event{ev}); err != nil {
				return stats, err
			}
		}
	}
	return stats, nil
}

// readResponse reads and validates one MBAP read response.
func readResponse(conn net.Conn, wantTxID uint16, wantFC uint8) ([]uint16, error) {
	header := make([]byte, 6)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}
	length := int(binary.BigEndian.Uint16(header[4:6]))
	if length < 2 || length > 1+maxPDUBytes {
		return nil, fmt.Errorf("%w: length %d", ErrBadMBAP, length)
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if proto := binary.BigEndian.Uint16(header[2:4]); proto != 0 {
		return nil, fmt.Errorf("%w: protocol id %d", ErrBadMBAP, proto)
	}
	if txID := binary.BigEndian.Uint16(header[0:2]); txID != wantTxID {
		return nil, fmt.Errorf("%w: transaction id %d, want %d", ErrBadMBAP, txID, wantTxID)
	}
	pdu := body[1:]
	if fc, isException := exceptionFunction(pdu); isException {
		return nil, fmt.Errorf("%w: exception response fc%d", ErrBadMBAP, fc)
	}
	values, err := parseReadResponse(pdu)
	if err != nil {
		return nil, err
	}
	if len(pdu) == 0 || pdu[0] != wantFC {
		return nil, fmt.Errorf("%w: function code mismatch", ErrBadMBAP)
	}
	return values, nil
}

func (a *Adapter) emitPollAssetSeen(ctx context.Context, sink ports.Sink) {
	host, _, err := net.SplitHostPort(a.target)
	if err != nil {
		return
	}
	ev, err := a.meta.AssetSeenEvent(domain.DeviceMeta{IP: host}, 0.6, a.now())
	if err != nil {
		return
	}
	if err := collect.EmitAll(ctx, sink, []domain.Event{ev}); err != nil {
		a.counters.IncError(err.Error())
	}
}

func portNumber(text string) int {
	var p int
	_, _ = fmt.Sscanf(text, "%d", &p)
	return p
}

// flowStats accumulates the traffic of one poll mode connection.
type flowStats struct {
	sentBytes   int64
	recvBytes   int64
	sentPackets int64
	recvPackets int64
}

func (f *flowStats) merge(other flowStats) {
	f.sentBytes += other.sentBytes
	f.recvBytes += other.recvBytes
	f.sentPackets += other.sentPackets
	f.recvPackets += other.recvPackets
}

func (a *Adapter) emitPollFlow(ctx context.Context, sink ports.Sink, stats *flowStats, conn net.Conn) {
	if conn == nil || (stats.sentPackets == 0 && stats.recvPackets == 0) {
		return
	}
	host, portText, err := net.SplitHostPort(a.target)
	if err != nil {
		return
	}
	local := conn.LocalAddr()
	if local == nil {
		return
	}
	localHost, localPortText, err := net.SplitHostPort(local.String())
	if err != nil {
		return
	}
	_ = localHost
	flow := domain.FlowMeta{
		SrcIP:     localHost,
		DstIP:     host,
		SrcPort:   portNumber(localPortText),
		DstPort:   portNumber(portText),
		Protocol:  "modbus_tcp",
		Bytes:     stats.sentBytes + stats.recvBytes,
		Packets:   stats.sentPackets + stats.recvPackets,
		Direction: "outbound",
	}
	ev, err := a.meta.FlowEvent(flow, 0.6, a.now())
	if err != nil {
		a.counters.IncError(err.Error())
		return
	}
	if err := collect.EmitAll(ctx, sink, []domain.Event{ev}); err != nil {
		a.counters.IncError(err.Error())
		return
	}
	*stats = flowStats{}
}
