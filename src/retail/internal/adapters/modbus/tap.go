// Passive MBAP stream decoder used by the tap mode and by the PCAP adapter.
package modbus

import (
	"errors"
	"fmt"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/collect"
	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

// TapOptions configures a passive decoder instance. One Tap is used per
// observed TCP connection so transaction correlation cannot mix connections.
type TapOptions struct {
	Meta      collect.Meta
	Registers []RegisterSpec
	// DeviceIP is optional passive identity evidence (set by the PCAP adapter
	// when the server address is known). Without it no asset_seen is invented.
	DeviceIP string
	// Peer is the textual peer used in write-attempt metadata (IP:port).
	Peer string
	// MaxBufferBytes bounds the reassembly buffer; default 64 KiB.
	MaxBufferBytes int
}

const (
	defaultTapBufferBytes = 64 << 10
	maxPendingReads       = 256
	maxWriteSeen          = 512
)

// Tap is a passive, non-sending MBAP stream decoder.
type Tap struct {
	opts TapOptions
	meta collect.Meta

	buf      []byte
	regIndex map[uint8]map[uint16]RegisterSpec

	pendingReads map[uint16]readRequest
	pendingOrder []uint16

	writeSeen  map[uint16]struct{}
	writeOrder []uint16

	assetSeen bool
	counters  collect.Counters
}

// NewTap creates a decoder. The meta provenance is validated immediately so an
// event construction error cannot appear later in the hot path.
func NewTap(opts TapOptions) (*Tap, error) {
	if err := opts.Meta.Validate(); err != nil {
		return nil, fmt.Errorf("modbus tap: %w", err)
	}
	if opts.MaxBufferBytes <= 0 {
		opts.MaxBufferBytes = defaultTapBufferBytes
	}
	if opts.MaxBufferBytes > 1<<20 {
		opts.MaxBufferBytes = 1 << 20
	}
	return &Tap{
		opts:         opts,
		meta:         opts.Meta,
		buf:          make([]byte, 0, 4096),
		regIndex:     indexRegisters(opts.Registers),
		pendingReads: make(map[uint16]readRequest, 32),
		writeSeen:    make(map[uint16]struct{}, 32),
	}, nil
}

// HealthCounters exposes the decoder's parser/unsupported counters to the
// owning collector.
func (t *Tap) HealthCounters() collect.CounterSnapshot { return t.counters.HealthCounters() }

// Feed appends raw stream bytes and returns the events decoded from complete
// frames. It never sends anything and never blocks.
func (t *Tap) Feed(chunk []byte, dir Direction) []domain.Event {
	if len(chunk) == 0 {
		return nil
	}
	if len(chunk) > t.opts.MaxBufferBytes {
		t.counters.IncParserError("input chunk exceeds reassembly limit")
		chunk = chunk[:t.opts.MaxBufferBytes]
	}
	t.buf = append(t.buf, chunk...)

	var events []domain.Event
	for len(t.buf) > 0 {
		frame, consumed, err := decodeMBAP(t.buf)
		if errors.Is(err, errNeedMoreData) {
			break
		}
		if err != nil {
			t.counters.IncParserError(err.Error())
			// Resynchronize one byte at a time; a stream tap may start in the
			// middle of a frame and must recover without dropping the connection.
			t.buf = t.buf[1:]
			continue
		}
		events = append(events, t.handleFrame(frame, dir)...)
		t.buf = t.buf[consumed:]
	}
	if len(t.buf) == 0 {
		t.buf = t.buf[:0]
	} else if cap(t.buf) > 2*t.opts.MaxBufferBytes {
		compact := make([]byte, len(t.buf))
		copy(compact, t.buf)
		t.buf = compact
	}
	return events
}

// Pending returns the number of unanswered read requests (diagnostics only).
func (t *Tap) Pending() int { return len(t.pendingReads) }

func (t *Tap) handleFrame(f Frame, dir Direction) []domain.Event {
	if len(f.PDU) == 0 {
		t.counters.IncParserError("empty pdu")
		return nil
	}
	now := t.meta.Now()
	events := t.maybeAssetSeen(now)
	if _, isException := exceptionFunction(f.PDU); isException {
		// A protocol error response is valid traffic, not a parser failure.
		return events
	}
	fc := f.PDU[0]
	switch {
	case isReadFunction(fc):
		events = append(events, t.handleRead(f, dir, now)...)
	case isObservedWriteFunction(fc):
		events = append(events, t.handleWrite(f, dir, now)...)
	default:
		t.counters.IncUnsupported()
	}
	return events
}

func (t *Tap) maybeAssetSeen(now time.Time) []domain.Event {
	if t.assetSeen || t.opts.DeviceIP == "" {
		return nil
	}
	t.assetSeen = true
	dev := domain.DeviceMeta{IP: t.opts.DeviceIP}
	ev, err := t.meta.AssetSeenEvent(dev, 0.5, now)
	if err != nil {
		t.counters.IncError(err.Error())
		return nil
	}
	return []domain.Event{ev}
}

func (t *Tap) handleRead(f Frame, dir Direction, now time.Time) []domain.Event {
	if len(f.PDU) == 5 && !isReadResponseShape(f.PDU) {
		if dir == DirectionToClient {
			t.counters.IncParserError("server sent a read request shaped pdu")
			return nil
		}
		req, err := parseReadRequest(f.PDU)
		if err != nil {
			t.counters.IncParserError(err.Error())
			return nil
		}
		t.rememberRead(f.TransactionID, req)
		return nil
	}
	if !isReadResponseShape(f.PDU) {
		t.counters.IncParserError("read pdu is neither request nor response")
		return nil
	}
	values, err := parseReadResponse(f.PDU)
	if err != nil {
		t.counters.IncParserError(err.Error())
		return nil
	}
	req, ok := t.takeRead(f.TransactionID)
	if !ok {
		// Without the request the register addresses are unknown; the values are
		// counted but must not be invented into measurements.
		t.counters.IncUnsupported()
		return nil
	}
	if req.Function != f.PDU[0] {
		t.counters.IncParserError("response function code does not match request")
		return nil
	}
	if len(values) < int(req.Quantity) {
		t.counters.IncParserError("response carries fewer registers than requested")
		return nil
	}
	byAddr := t.regIndex[req.Function]
	if len(byAddr) == 0 {
		return nil
	}
	events := make([]domain.Event, 0, 4)
	for i := 0; i < int(req.Quantity); i++ {
		addr := req.Address + uint16(i)
		spec, mapped := byAddr[addr]
		if !mapped {
			continue
		}
		meas := domain.Measurement{
			Value:      scaleRaw(values[i], spec),
			Unit:       spec.Unit,
			Quality:    domain.QualityGood,
			Metric:     spec.Metric,
			ObservedAt: now,
		}
		ev, err := t.meta.TelemetryEvent(spec.SensorID, spec.AssetID, meas, 0.7, now)
		if err != nil {
			t.counters.IncError(err.Error())
			continue
		}
		events = append(events, ev)
	}
	return events
}

func (t *Tap) handleWrite(f Frame, dir Direction, now time.Time) []domain.Event {
	if dir == DirectionToClient {
		// Write responses echo the request; the attempt was already seen when the
		// request travelled toward the server.
		return nil
	}
	if dir == DirectionUnknown {
		if _, dup := t.writeSeen[f.TransactionID]; dup {
			return nil
		}
		t.rememberWrite(f.TransactionID)
	}
	fc := f.PDU[0]
	attempt := domain.WriteAttempt{
		Protocol: "modbus_tcp",
		Source:   t.opts.Peer,
		Target:   fmt.Sprintf("unit:%d", f.UnitID),
		Function: writeFunctionName(fc),
		Allowed:  false, // no write allowlist exists in this product
	}
	if addr, ok := writeRegisterAddress(fc, f.PDU); ok {
		attempt.Register = observedRegisterName(fc, addr)
	}
	if count, ok := writeRegisterCount(fc, f.PDU); ok {
		// Coarse hint only: the written process value is intentionally not stored.
		attempt.ValueHint = fmt.Sprintf("items=%d", count)
	}
	ev, err := t.meta.WriteAttemptEvent(attempt, 0.8, now)
	if err != nil {
		t.counters.IncError(err.Error())
		return nil
	}
	return []domain.Event{ev}
}

func observedRegisterName(fc uint8, addr uint16) string {
	switch fc {
	case fcWriteSingleCoil, fcWriteMultipleCoils:
		return fmt.Sprintf("coil:%d", 1+int(addr))
	default:
		return fmt.Sprintf("holding:%d", 40001+int(addr))
	}
}

func (t *Tap) rememberRead(txID uint16, req readRequest) {
	if _, exists := t.pendingReads[txID]; !exists {
		if len(t.pendingOrder) >= maxPendingReads {
			oldest := t.pendingOrder[0]
			t.pendingOrder = t.pendingOrder[1:]
			delete(t.pendingReads, oldest)
		}
		t.pendingOrder = append(t.pendingOrder, txID)
	}
	t.pendingReads[txID] = req
}

func (t *Tap) takeRead(txID uint16) (readRequest, bool) {
	req, ok := t.pendingReads[txID]
	if !ok {
		return readRequest{}, false
	}
	delete(t.pendingReads, txID)
	for i, id := range t.pendingOrder {
		if id == txID {
			t.pendingOrder = append(t.pendingOrder[:i], t.pendingOrder[i+1:]...)
			break
		}
	}
	return req, true
}

func (t *Tap) rememberWrite(txID uint16) {
	if len(t.writeOrder) >= maxWriteSeen {
		oldest := t.writeOrder[0]
		t.writeOrder = t.writeOrder[1:]
		delete(t.writeSeen, oldest)
	}
	t.writeOrder = append(t.writeOrder, txID)
	t.writeSeen[txID] = struct{}{}
}
