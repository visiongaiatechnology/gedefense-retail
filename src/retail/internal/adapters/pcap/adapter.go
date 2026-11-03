// PCAP collector: offline import of capture files with deterministic dispatch
// into the Modbus, MQTT, BACnet/IP, HTTP-UI and flow/asset decoders.
package pcap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/adapters/bacnet"
	"github.com/visiongaiatechnology/gedefense/retail/internal/adapters/modbus"
	"github.com/visiongaiatechnology/gedefense/retail/internal/adapters/mqtt"
	"github.com/visiongaiatechnology/gedefense/retail/internal/collect"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
)

const adapterVersion = "1"

// Option keys owned by the adapter.
const (
	optFiles     = "files"
	optDir       = "dir"
	optRegs      = "registers"
	optSensors   = "sensors"
	optObjects   = "objects"
	optHTTPPorts = "http_ports"
)

const (
	maxImportedFiles  = 64
	maxConnectionCap  = 4096
	finalFlushTimeout = 2 * time.Second
)

// ErrNoInput is returned when neither files nor dir is configured.
var ErrNoInput = errors.New("pcap: option files or dir is required")

// Adapter is the offline PCAP collector.
type Adapter struct {
	cfg     collect.AdapterConfig
	meta    collect.Meta
	files   []string
	decoder *dispatcher
}

// New creates the adapter. It resolves the input paths but does not read them.
func New(cfg collect.AdapterConfig) (ports.Collector, error) {
	site, err := cfg.ResolveSite()
	if err != nil {
		return nil, err
	}
	a := &Adapter{cfg: cfg}
	a.meta = collect.Meta{
		SiteID:     site,
		ZoneID:     cfg.ZoneID,
		Source:     cfg.AdapterID,
		Collection: collect.CollectionOperatorExport,
		Protocol:   "pcap",
		Clock:      cfg.Clock,
	}
	if err := a.meta.Validate(); err != nil {
		return nil, fmt.Errorf("pcap %q: %w", cfg.AdapterID, err)
	}
	files, err := resolveInputs(cfg)
	if err != nil {
		return nil, fmt.Errorf("pcap %q: %w", cfg.AdapterID, err)
	}
	a.files = files

	registers, err := modbus.ParseRegisterSpec(cfg.Option(optRegs))
	if err != nil {
		return nil, fmt.Errorf("pcap %q: %w", cfg.AdapterID, err)
	}
	mappings, err := mqtt.ParseTopicMappings(cfg.Option(optSensors))
	if err != nil {
		return nil, fmt.Errorf("pcap %q: %w", cfg.AdapterID, err)
	}
	objects, err := bacnet.ParseObjectMappings(cfg.Option(optObjects))
	if err != nil {
		return nil, fmt.Errorf("pcap %q: %w", cfg.AdapterID, err)
	}
	httpPorts, err := parseHTTPPorts(cfg.Option(optHTTPPorts))
	if err != nil {
		return nil, fmt.Errorf("pcap %q: %w", cfg.AdapterID, err)
	}
	dispatcher, err := newDispatcher(dispatchConfig{
		Meta:           a.meta,
		ModbusRegs:     registers,
		MQTTMappings:   mappings,
		BacnetMappings: objects,
		HTTPPorts:      httpPorts,
	})
	if err != nil {
		return nil, fmt.Errorf("pcap %q: %w", cfg.AdapterID, err)
	}
	a.decoder = dispatcher
	return a, nil
}

// resolveInputs expands the configured files/dir into a sorted, bounded list.
func resolveInputs(cfg collect.AdapterConfig) ([]string, error) {
	var files []string
	if raw := cfg.Option(optFiles); raw != "" {
		for _, entry := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ';' }) {
			entry = strings.TrimSpace(entry)
			if entry == "" {
				continue
			}
			files = append(files, filepath.Clean(entry))
		}
	}
	if raw := cfg.Option(optDir); raw != "" {
		dir := filepath.Clean(strings.TrimSpace(raw))
		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil, fmt.Errorf("read dir %q: %w", dir, err)
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := strings.ToLower(entry.Name())
			if !strings.HasSuffix(name, ".pcap") && !strings.HasSuffix(name, ".cap") {
				continue
			}
			files = append(files, filepath.Join(dir, entry.Name()))
		}
		sort.Strings(files)
	}
	if len(files) == 0 {
		return nil, ErrNoInput
	}
	if len(files) > maxImportedFiles {
		return nil, fmt.Errorf("pcap: at most %d files per adapter", maxImportedFiles)
	}
	for _, file := range files {
		info, err := os.Stat(file)
		if err != nil {
			return nil, fmt.Errorf("stat %q: %w", file, err)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("pcap: %q is not a regular file", file)
		}
	}
	return files, nil
}

// Info implements ports.Collector.
func (a *Adapter) Info() ports.Info {
	return ports.Info{
		AdapterID:  a.cfg.AdapterID,
		Version:    adapterVersion,
		Protocols:  []string{"pcap", "modbus_tcp", "mqtt", "bacnet_ip", "http", "https", "snmp"},
		Collection: collect.CollectionOperatorExport,
		ReadOnly:   true,
		Description: "Offline PCAP import (LE/BE, Ethernet/VLAN/IPv4/TCP+UDP) producing flow and asset events and " +
			"dispatching payloads into the passive Modbus/MQTT/BACnet/HTTP decoders; never sends a packet.",
	}
}

// Start implements ports.Collector. It imports every file once and then waits
// for ctx cancellation; it never opens a network socket.
func (a *Adapter) Start(ctx context.Context, sink ports.Sink) error {
	if ctx == nil {
		return errors.New("pcap: nil context")
	}
	if sink == nil {
		return errors.New("pcap: nil sink")
	}
	for _, file := range a.files {
		if err := ctx.Err(); err != nil {
			break
		}
		if err := a.importFile(ctx, sink, file); err != nil {
			a.decoder.counters.IncError(fmt.Sprintf("%s: %v", filepath.Base(file), err))
		}
	}
	// The final aggregation is evidence that must not be lost on graceful
	// shutdown: flush with a detached, bounded context. Emitting with the
	// already cancelled parent context would silently drop every flow and
	// asset hypothesis of the imported capture.
	flushCtx, flushCancel := context.WithTimeout(context.WithoutCancel(ctx), finalFlushTimeout)
	defer flushCancel()
	if err := a.decoder.flush(flushCtx, sink); err != nil {
		a.decoder.counters.IncError(err.Error())
	}
	<-ctx.Done()
	return nil
}

// importFile streams one pcap file through the decoder.
func (a *Adapter) importFile(ctx context.Context, sink ports.Sink, file string) error {
	f, err := os.Open(file)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer func() { _ = f.Close() }()
	reader, err := NewReader(f)
	if err != nil {
		return fmt.Errorf("read header: %w", err)
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		record, err := reader.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("record %d: %w", reader.Records()+1, err)
		}
		pkt, err := Decode(reader.LinkType(), record.Data, record.Timestamp)
		if err != nil {
			switch {
			case errors.Is(err, ErrNotIPv4), errors.Is(err, ErrUnsupportedIP):
				a.decoder.counters.IncUnsupported()
			default:
				a.decoder.counters.IncParserError(err.Error())
			}
			continue
		}
		if err := a.decoder.handle(ctx, sink, pkt); err != nil {
			return err
		}
	}
}

// HealthCounters implements collect.Instrumented.
func (a *Adapter) HealthCounters() collect.CounterSnapshot { return a.decoder.HealthCounters() }

func parseHTTPPorts(raw string) (map[uint16]bool, error) {
	ports := make(map[uint16]bool, 5)
	if strings.TrimSpace(raw) == "" {
		for _, port := range []uint16{80, 8000, 8080, 443, 8443} {
			ports[port] = true
		}
		return ports, nil
	}
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		var port int
		if _, err := fmt.Sscanf(entry, "%d", &port); err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("option %s: invalid port %q", optHTTPPorts, entry)
		}
		ports[uint16(port)] = true
	}
	if len(ports) == 0 {
		return nil, fmt.Errorf("option %s: no ports", optHTTPPorts)
	}
	return ports, nil
}
