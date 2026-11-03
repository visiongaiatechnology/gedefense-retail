// Passive HTTP/1.x metadata decoder.
package httpui

import (
	"bytes"
	"strconv"
	"strings"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/collect"
	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

// DecoderOptions configures one passive decoder instance (one connection).
type DecoderOptions struct {
	Meta      collect.Meta
	MaxHeader int
}

// Decoder sniffs whether a stream carries plaintext HTTP or TLS and extracts
// only the documented metadata. One decoder belongs to exactly one connection.
type Decoder struct {
	opts     DecoderOptions
	counters collect.Counters
	mode     uint8 // 0 unknown, 1 http, 2 tls
	httpBuf  []byte
	skipBody int64
	tls      tlsState
}

const (
	modeUnknown uint8 = iota
	modeHTTP
	modeTLS
)

// NewDecoder creates a decoder; the meta provenance is validated once.
func NewDecoder(opts DecoderOptions) (*Decoder, error) {
	if err := opts.Meta.Validate(); err != nil {
		return nil, err
	}
	if opts.MaxHeader <= 0 {
		opts.MaxHeader = defaultMaxHeaderBytes
	}
	return &Decoder{opts: opts}, nil
}

// HealthCounters exposes parser counters to the owning collector.
func (d *Decoder) HealthCounters() collect.CounterSnapshot { return d.counters.HealthCounters() }

// Feed consumes one raw TCP payload chunk and returns decoded events.
func (d *Decoder) Feed(meta ConnMeta, chunk []byte) []domain.Event {
	if len(chunk) == 0 {
		return nil
	}
	if d.mode == modeUnknown {
		if chunk[0] == tlsContentTypeHello {
			d.mode = modeTLS
		} else {
			d.mode = modeHTTP
		}
	}
	if d.mode == modeTLS {
		return d.feedTLS(meta, chunk)
	}
	return d.feedHTTP(meta, chunk)
}

// feedHTTP buffers until a complete header block is available. Bodies are
// skipped via Content-Length; they are never stored.
func (d *Decoder) feedHTTP(meta ConnMeta, chunk []byte) []domain.Event {
	d.httpBuf = append(d.httpBuf, chunk...)
	if len(d.httpBuf) > d.opts.MaxHeader {
		d.counters.IncParserError("http header exceeds limit")
		d.httpBuf = d.httpBuf[:0]
		d.skipBody = 0
		return nil
	}
	var events []domain.Event
	for {
		if d.skipBody > 0 {
			consume := int64(len(d.httpBuf))
			if consume > d.skipBody {
				consume = d.skipBody
			}
			d.httpBuf = d.httpBuf[consume:]
			d.skipBody -= consume
			if d.skipBody > 0 {
				break
			}
		}
		idx, ok := headerBlockEnd(d.httpBuf)
		if !ok {
			break
		}
		block := make([]byte, idx)
		copy(block, d.httpBuf[:idx])
		rest := d.httpBuf[idx+4:]
		d.httpBuf = append(make([]byte, 0, len(rest)), rest...)
		events = append(events, d.parseHTTPBlock(meta, block)...)
	}
	if len(d.httpBuf) == 0 {
		d.httpBuf = d.httpBuf[:0]
	}
	return events
}

// parseHTTPBlock interprets exactly one header block.
func (d *Decoder) parseHTTPBlock(meta ConnMeta, block []byte) []domain.Event {
	now := d.opts.Meta.Now()
	if len(block) == 0 || len(block) > d.opts.MaxHeader {
		d.counters.IncParserError("empty http header block")
		return nil
	}
	lines := bytes.Split(block, []byte("\r\n"))
	first := strings.TrimSpace(string(lines[0]))
	if first == "" {
		d.counters.IncParserError("empty http start line")
		return nil
	}
	headers := parseHeaders(lines[1:])
	if strings.HasPrefix(first, "HTTP/") {
		return d.responseEvents(meta, block, first, headers, now)
	}
	return d.requestEvents(meta, block, first, headers, now)
}

// parseHeaders keeps only the documented, non-sensitive header allowlist.
func parseHeaders(lines [][]byte) map[string]string {
	out := make(map[string]string, 6)
	for _, line := range lines {
		keyRaw, valueRaw, ok := bytes.Cut(line, []byte(":"))
		if !ok {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(string(keyRaw)))
		value := strings.TrimSpace(string(valueRaw))
		if len(value) > 256 {
			value = value[:256]
		}
		switch key {
		case "host", "user-agent", "server", "content-type", "content-length":
			if _, exists := out[key]; !exists {
				out[key] = value
			}
		}
	}
	return out
}

func (d *Decoder) requestEvents(meta ConnMeta, block []byte, startLine string, headers map[string]string, now time.Time) []domain.Event {
	fields := strings.Fields(startLine)
	if len(fields) < 2 {
		d.counters.IncParserError("malformed http request line")
		return nil
	}
	method := strings.ToUpper(fields[0])
	if len(method) < 3 || len(method) > 10 || !isAlpha(method) {
		d.counters.IncParserError("invalid http method")
		return nil
	}
	path := sanitizePath(fields[1])
	// Never store the body: only its length is consumed.
	if length := headerInt(headers["content-length"]); length > 0 && length <= 1<<20 {
		d.skipBody = int64(length)
	}

	events := make([]domain.Event, 0, 3)
	flow := domain.FlowMeta{
		SrcIP:     meta.ClientIP,
		DstIP:     meta.ServerIP,
		SrcPort:   int(meta.ClientPort),
		DstPort:   int(meta.ServerPort),
		Protocol:  "http",
		Bytes:     int64(len(block) + 4),
		Packets:   1,
		Direction: "internal",
	}
	if meta.Valid() {
		if ev, err := d.opts.Meta.FlowEvent(flow, 0.6, now); err == nil {
			events = append(events, ev)
		}
	}
	if host := sanitizeHost(headers["host"]); host != "" && meta.Valid() {
		vendor, model := uiHint(host)
		confidence := 0.45
		if vendor != "" || model != "" {
			confidence = 0.6
		}
		dev := domain.DeviceMeta{IP: meta.ServerIP, Hostname: host, Vendor: vendor, Model: model}
		if ev, err := d.opts.Meta.AssetSeenEvent(dev, confidence, now); err == nil {
			events = append(events, ev)
		}
	}
	if isWriteMethod(method) {
		attempt := domain.WriteAttempt{
			Protocol: "http",
			Source:   dialString(meta.ClientIP, meta.ClientPort),
			Target:   dialString(meta.ServerIP, meta.ServerPort),
			Function: "http_" + strings.ToLower(method),
			Register: path, // path only: no query string, no body, no credentials
			Allowed:  false,
		}
		if ev, err := d.opts.Meta.WriteAttemptEvent(attempt, 0.7, now); err == nil {
			events = append(events, ev)
		}
	}
	return events
}

func (d *Decoder) responseEvents(meta ConnMeta, block []byte, startLine string, headers map[string]string, now time.Time) []domain.Event {
	fields := strings.Fields(startLine)
	if len(fields) < 2 {
		d.counters.IncParserError("malformed http status line")
		return nil
	}
	statusCode, err := strconv.Atoi(fields[1])
	if err != nil || statusCode < 100 || statusCode > 599 {
		d.counters.IncParserError("invalid http status code")
		return nil
	}
	events := make([]domain.Event, 0, 2)
	if meta.Valid() {
		flow := domain.FlowMeta{
			SrcIP:     meta.ServerIP,
			DstIP:     meta.ClientIP,
			SrcPort:   int(meta.ServerPort),
			DstPort:   int(meta.ClientPort),
			Protocol:  "http",
			Bytes:     int64(len(block) + 4),
			Packets:   1,
			Direction: "internal",
		}
		if ev, err := d.opts.Meta.FlowEvent(flow, 0.6, now); err == nil {
			events = append(events, ev)
		}
	}
	server := sanitizeToken(headers["server"], 128)
	if server != "" {
		vendor, model := uiHint(server)
		confidence := 0.45
		if vendor != "" || model != "" {
			confidence = 0.6
		}
		dev := domain.DeviceMeta{IP: meta.ServerIP, Vendor: vendor, Model: model}
		if ev, err := d.opts.Meta.AssetSeenEvent(dev, confidence, now); err == nil {
			events = append(events, ev)
		}
	}
	return events
}

func headerInt(raw string) int {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v < 0 {
		return 0
	}
	return v
}

func isWriteMethod(method string) bool {
	switch method {
	case "POST", "PUT", "PATCH", "DELETE":
		return true
	}
	return false
}

func isAlpha(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') {
			return false
		}
	}
	return true
}

func dialString(ip string, port uint16) string {
	if port == 0 {
		return ip
	}
	return ip + ":" + strconv.Itoa(int(port))
}
