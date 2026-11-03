// Per-connection enforcement loop. Requests and responses are forwarded
// byte-identically: the proxy validates MBAP framing and authorizes writes, it
// never re-encodes a protocol data unit.
package modbusproxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// upstream is the gate-owned connection to one controller. Exactly one request
// may be outstanding on it (strict serialization).
type upstream struct {
	conn   net.Conn
	reader *bufio.Reader
}

// handleConn terminates one vendor connection.
func (p *Proxy) handleConn(ctx context.Context, client net.Conn) {
	clientIP := hostOnly(client.RemoteAddr())
	reader := bufio.NewReaderSize(client, 8<<10)
	var up *upstream
	defer func() { p.dropUpstream(&up) }()

	for {
		if ctx.Err() != nil {
			return
		}
		if err := client.SetReadDeadline(time.Now().Add(p.cfg.IdleTimeout)); err != nil {
			return
		}
		f, err := readFrame(reader)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				p.recordError("client idle timeout")
				return
			}
			if errors.Is(err, ErrBadFrame) {
				// No resynchronization: a second framing interpretation would
				// allow frame smuggling.
				p.parserErrors.Add(1)
				p.recordError("client frame: " + err.Error())
			}
			return
		}
		p.requests.Add(1)
		closeConn := false
		switch fc := f.function(); {
		case isWriteFunction(fc):
			closeConn = p.handleWrite(ctx, client, clientIP, &up, f)
		case isReadFunction(fc):
			p.handleRead(ctx, client, clientIP, &up, f)
		default:
			p.unsupported.Add(1)
			p.respondException(client, f, exIllegalFunction)
		}
		if closeConn {
			return
		}
	}
}

// handleWrite applies the fail-closed write policy. It returns true when the
// connection must be closed (audit/store failure: no clean exception round trip
// may suggest that the request was processed).
func (p *Proxy) handleWrite(ctx context.Context, client net.Conn, clientIP string, up **upstream, f frame) bool {
	intent, err := decodeWrite(f.PDU)
	if err != nil {
		p.parserErrors.Add(1)
		p.recordError("write pdu: " + err.Error())
		p.respondException(client, f, exIllegalDataValue)
		return false
	}
	denyLocal := func(reason string, code uint8) {
		p.writesDenied.Add(1)
		p.deny(ctx, clientIP, intent, writeDecision{reason: reason, exception: code})
		p.respondException(client, f, code)
	}
	if p.cfg.ReadOnlyMode {
		denyLocal(ReasonOperationNotApproved, exIllegalFunction)
		return false
	}
	// Unit ids must be explicitly allowed; there is no silent rewriting.
	if !p.unitAllowed(f.UnitID) {
		denyLocal(ReasonWrongTarget, exIllegalFunction)
		return false
	}
	if !sourceAllowed(p.cfg.SourceCIDRs, clientIP) {
		denyLocal(ReasonWrongSource, exIllegalFunction)
		return false
	}
	decision := p.authorizeWrite(ctx, clientIP, intent)
	if !decision.allowed {
		p.writesDenied.Add(1)
		p.deny(ctx, clientIP, intent, decision)
		if decision.reason == ReasonFailsafeStore {
			// Fail-closed: an audit failure must not look like a normal Modbus
			// refusal (no retry hint, no "device said no").
			p.recordError("audit failure: write denied and connection closed")
			return true
		}
		p.respondException(client, f, decision.exception)
		return false
	}
	// Authorization succeeded; the validated ADU is forwarded byte-identically.
	responseRaw, err := p.transact(ctx, up, f)
	if err != nil {
		p.upstreamErrors.Add(1)
		p.recordError("upstream write: " + err.Error())
		p.reportWriteUnknown(ctx, decision, "upstream_error")
		p.respondException(client, f, exGatewayTarget)
		return false
	}
	p.writesAllowed.Add(1)
	p.respondRaw(client, responseRaw)
	return false
}

// handleRead forwards a read request if the source CIDR, the unit allowlist and
// the configured register window allow it.
func (p *Proxy) handleRead(ctx context.Context, client net.Conn, clientIP string, up **upstream, f frame) {
	denyRead := func(code uint8) {
		p.readsDenied.Add(1)
		p.respondException(client, f, code)
	}
	if !p.unitAllowed(f.UnitID) {
		denyRead(exIllegalDataAddress)
		return
	}
	if !sourceAllowed(p.cfg.SourceCIDRs, clientIP) {
		denyRead(exIllegalDataAddress)
		return
	}
	fc := f.function()
	allowed := false
	switch fc {
	case FCReadExceptionStatus, FCReportSlaveID:
		allowed = p.cfg.ReadRegisters != nil
	default:
		reqFC, start, count, ok := parseReadRange(f.PDU)
		if !ok {
			p.parserErrors.Add(1)
			p.respondException(client, f, exIllegalDataValue)
			return
		}
		allowed = readAllowed(p.cfg.ReadRegisters, reqFC, start, count)
	}
	if !allowed {
		denyRead(exIllegalDataAddress)
		return
	}
	responseRaw, err := p.transact(ctx, up, f)
	if err != nil {
		p.upstreamErrors.Add(1)
		p.recordError("upstream read: " + err.Error())
		p.respondException(client, f, exGatewayTarget)
		return
	}
	p.reads.Add(1)
	p.respondRaw(client, responseRaw)
}

// transact forwards one validated ADU to the controller and returns the exact
// response ADU. It never retries (writes are not idempotent; reads are retried
// by the client, not by the gate).
func (p *Proxy) transact(ctx context.Context, up **upstream, f frame) ([]byte, error) {
	if len(f.Raw) < 7 || len(f.Raw) > 6+maxMBAPLength {
		return nil, fmt.Errorf("%w: refusing to forward a %d byte adu", ErrBadFrame, len(f.Raw))
	}
	if *up == nil {
		dialer := net.Dialer{Timeout: p.cfg.Timeout}
		conn, err := dialer.DialContext(ctx, "tcp", p.cfg.Upstream)
		if err != nil {
			return nil, fmt.Errorf("dial %s: %w", p.cfg.Upstream, err)
		}
		if !p.trackConn(conn) {
			_ = conn.Close()
			return nil, errors.New("upstream connection limit or shutdown")
		}
		*up = &upstream{conn: conn, reader: bufio.NewReaderSize(conn, 8<<10)}
	}
	conn := (*up).conn
	if err := conn.SetDeadline(time.Now().Add(p.cfg.Timeout)); err != nil {
		p.dropUpstream(up)
		return nil, err
	}
	if _, err := conn.Write(f.Raw); err != nil {
		p.dropUpstream(up)
		return nil, fmt.Errorf("write: %w", err)
	}
	response, err := readFrame((*up).reader)
	if err != nil {
		p.dropUpstream(up)
		return nil, fmt.Errorf("read response: %w", err)
	}
	if response.TransactionID != f.TransactionID {
		// Transaction ids are only valid for response correlation on the same
		// connection; they are never used as an idempotency key.
		p.dropUpstream(up)
		return nil, fmt.Errorf("transaction id mismatch: got %d want %d", response.TransactionID, f.TransactionID)
	}
	if len(response.PDU) == 0 {
		p.dropUpstream(up)
		return nil, errors.New("empty response pdu")
	}
	want := f.function()
	got := response.PDU[0]
	if got != want && got != want|0x80 {
		p.dropUpstream(up)
		return nil, fmt.Errorf("function code mismatch: got %d want %d", got, want)
	}
	return response.Raw, nil
}

// reportWriteUnknown reports a write whose effect is unknown (timeout after the
// ADU was forwarded). It is never retried. The optional seam is implemented by
// the gate core (Alpha extension, documented).
func (p *Proxy) reportWriteUnknown(ctx context.Context, decision writeDecision, detail string) {
	reporter, ok := p.sessions.(WriteUnknownReporter)
	if !ok {
		return
	}
	for _, op := range decision.ops {
		if err := reporter.WriteUnknown(ctx, decision.session.SessionID, op, detail); err != nil {
			p.recordError("write_unknown report: " + err.Error())
		}
	}
}

// dropUpstream closes and forgets the upstream connection.
func (p *Proxy) dropUpstream(up **upstream) {
	if up == nil || *up == nil {
		return
	}
	conn := (*up).conn
	_ = conn.Close()
	p.untrackConn(conn)
	*up = nil
}

// respondRaw writes exact ADU bytes to the client.
func (p *Proxy) respondRaw(client net.Conn, adu []byte) {
	if len(adu) == 0 {
		return
	}
	if err := client.SetWriteDeadline(time.Now().Add(p.cfg.Timeout)); err != nil {
		return
	}
	if _, err := client.Write(adu); err != nil {
		p.recordError("client write: " + err.Error())
	}
}

// respondException answers locally. This is the only path for a denied write:
// the request ADU is never forwarded upstream.
func (p *Proxy) respondException(client net.Conn, f frame, code uint8) {
	fc := f.function()
	p.respondRaw(client, exceptionADU(f.TransactionID, f.UnitID, fc, code))
}

// hostOnly extracts the IP part of a net.Addr.
func hostOnly(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return ""
	}
	return host
}
