// pcap subcommand: deterministic scenario PCAP fixtures for the test suite.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	pcapdb "github.com/visiongaiatechnology/gedefense/retail/internal/adapters/pcap"
)

var (
	simBroadcastIP = "172.16.50.255"
	simBaseTime    = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
)

// simFrame is one synthetic captured frame.
type simFrame struct {
	at   time.Time
	data []byte
}

// runPCAP writes the scenario fixtures and verifies each file by re-reading it.
func runPCAP(args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("pcap", stderr)
	out := fs.String("out", filepath.Join("..", "..", "tests", "testdata", "pcap"), "output directory")
	scenario := fs.String("scenario", "all", "all|normal|angriff|angriff-management-ui")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var names []string
	switch *scenario {
	case "all":
		names = []string{"normal", "angriff", "angriff-management-ui"}
	case "normal", "angriff", "angriff-management-ui":
		names = []string{*scenario}
	default:
		return fmt.Errorf("pcap: unknown scenario %q", *scenario)
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		return fmt.Errorf("pcap: create output dir: %w", err)
	}
	for _, name := range names {
		frames, err := scenarioFrames(name)
		if err != nil {
			return fmt.Errorf("pcap: scenario %s: %w", name, err)
		}
		path := filepath.Join(*out, name+".pcap")
		if err := writePCAP(path, frames); err != nil {
			return fmt.Errorf("pcap: write %s: %w", name, err)
		}
		packets, err := verifyPCAP(path)
		if err != nil {
			return fmt.Errorf("pcap: verify %s: %w", name, err)
		}
		info, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("pcap: stat %s: %w", name, err)
		}
		fmt.Fprintf(stdout, "PCAP_SUMMARY file=%s scenario=%s packets=%d bytes=%d\n",
			path, name, packets, info.Size())
	}
	return nil
}

// writePCAP writes the frames with the classic little-endian pcap header.
func writePCAP(path string, frames []simFrame) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	writer, err := pcapdb.NewWriter(file)
	if err != nil {
		return err
	}
	for _, frame := range frames {
		if err := writer.WritePacket(frame.at, frame.data); err != nil {
			return err
		}
	}
	return file.Sync()
}

// verifyPCAP re-reads the file and decodes every packet; it fails when the
// generated fixture is not a readable capture.
func verifyPCAP(path string) (int, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer func() { _ = file.Close() }()
	reader, err := pcapdb.NewReader(file)
	if err != nil {
		return 0, err
	}
	packets := 0
	for {
		record, err := reader.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return packets, err
		}
		if _, err := pcapdb.Decode(reader.LinkType(), record.Data, record.Timestamp); err != nil {
			// Non-IP frames are allowed; structural decode errors are not.
			var decodeErr error = err
			if errors.Is(decodeErr, pcapdb.ErrNotIPv4) || errors.Is(decodeErr, pcapdb.ErrUnsupportedIP) {
				continue
			}
			return packets, fmt.Errorf("packet %d: %v", packets+1, err)
		}
		packets++
	}
	return packets, nil
}

// scenarioFrames builds the deterministic frame list of one scenario.
func scenarioFrames(name string) ([]simFrame, error) {
	seq := &frameSeq{}
	switch name {
	case "normal":
		appendNormalFrames(seq)
	case "angriff":
		appendNormalFrames(seq)
		appendAttackFrames(seq)
	case "angriff-management-ui":
		appendNormalFrames(seq)
		appendManagementUIAttackFrames(seq)
	default:
		return nil, fmt.Errorf("unknown scenario %q", name)
	}
	return seq.frames, nil
}

// frameSeq appends frames with a deterministic timestamp sequence.
type frameSeq struct {
	frames []simFrame
	tcpSeq uint32
}

func (s *frameSeq) next() time.Time {
	at := simBaseTime.Add(time.Duration(len(s.frames)) * 250 * time.Millisecond)
	s.tcpSeq += 4096
	return at
}

func (s *frameSeq) tcp(srcMAC, dstMAC [6]byte, srcIP string, srcPort uint16, dstIP string, dstPort uint16, flags uint8, payload []byte) {
	frame, err := pcapdb.BuildEthernetIPv4TCP(dstMAC, srcMAC,
		endpoint(srcIP, srcPort), endpoint(dstIP, dstPort), s.tcpSeq, 1, flags, payload)
	if err != nil {
		return
	}
	s.frames = append(s.frames, simFrame{at: s.next(), data: frame})
}

func (s *frameSeq) udp(srcMAC, dstMAC [6]byte, srcIP string, srcPort uint16, dstIP string, dstPort uint16, payload []byte) {
	frame, err := pcapdb.BuildEthernetIPv4UDP(dstMAC, srcMAC,
		endpoint(srcIP, srcPort), endpoint(dstIP, dstPort), payload)
	if err != nil {
		return
	}
	s.frames = append(s.frames, simFrame{at: s.next(), data: frame})
}

// appendNormalFrames is the benign baseline traffic (Modbus reads, BACnet I-Am,
// MQTT telemetry, HTTP/HTTPS management polls).
func appendNormalFrames(s *frameSeq) {
	s.tcp(macPanel, macController, simPanelIP, 50000, simControllerIP, 502, pcapdb.TCPFlagPSH|pcapdb.TCPFlagACK,
		buildModbusReadRequest(1, 1, 3, 0, 5))
	s.tcp(macController, macPanel, simControllerIP, 502, simPanelIP, 50000, pcapdb.TCPFlagPSH|pcapdb.TCPFlagACK,
		buildModbusReadResponse(1, 1, 3, []uint16{42, 40, 0, 0, 0}))
	s.tcp(macPanel, macController, simPanelIP, 50000, simControllerIP, 502, pcapdb.TCPFlagPSH|pcapdb.TCPFlagACK,
		buildModbusReadRequest(2, 1, 4, 0, 3))
	s.tcp(macController, macPanel, simControllerIP, 502, simPanelIP, 50000, pcapdb.TCPFlagPSH|pcapdb.TCPFlagACK,
		buildModbusReadResponse(2, 1, 4, []uint16{42, 39, 44}))

	s.udp(macController, macPanel, simControllerIP, 47808, simBroadcastIP, 47808, buildBACnetIAm(1001, 5))
	s.udp(macController, macPanel, simControllerIP, 47808, simPanelIP, 50001, buildBACnetReadPropertyAck(0, 1, 85, 4.2))

	s.tcp(macPanel, macBroker, simPanelIP, 50002, simBrokerIP, 1883, pcapdb.TCPFlagPSH|pcapdb.TCPFlagACK,
		buildMQTTConnect("panel-01"))
	s.tcp(macPanel, macBroker, simPanelIP, 50002, simBrokerIP, 1883, pcapdb.TCPFlagPSH|pcapdb.TCPFlagACK,
		buildMQTTSubscribe(1, "store/filiale-001/freezer/temp"))
	s.tcp(macBroker, macPanel, simBrokerIP, 1883, simPanelIP, 50002, pcapdb.TCPFlagPSH|pcapdb.TCPFlagACK,
		buildMQTTPublish("store/filiale-001/freezer/temp", []byte("4.2")))

	s.tcp(macPanel, macController, simPanelIP, 50003, simControllerIP, 80, pcapdb.TCPFlagPSH|pcapdb.TCPFlagACK,
		buildHTTPRequest("GET", "/", "storeview-ak-sm-800.filiale.local", "panel-01"))
	s.tcp(macController, macPanel, simControllerIP, 80, simPanelIP, 50003, pcapdb.TCPFlagPSH|pcapdb.TCPFlagACK,
		buildHTTPResponse(200, "OK", "StoreView"))

	s.tcp(macPanel, macController, simPanelIP, 50004, simControllerIP, 8443, pcapdb.TCPFlagPSH|pcapdb.TCPFlagACK,
		buildTLSClientHello("storeview-ak-sm-800.filiale.local"))
}

// appendAttackFrames is the synthetic OT attack traffic (observed-only).
func appendAttackFrames(s *frameSeq) {
	// Foreign peer writes a setpoint (FC6) — reported as write_attempt only.
	s.tcp(macForeign, macController, simForeignIP, 50010, simControllerIP, 502, pcapdb.TCPFlagPSH|pcapdb.TCPFlagACK,
		buildModbusWriteSingleRegister(99, 1, 1, 120))
	// Device echo of the write (must not be double-counted by the tap decoder).
	s.tcp(macController, macForeign, simControllerIP, 502, simForeignIP, 50010, pcapdb.TCPFlagPSH|pcapdb.TCPFlagACK,
		buildModbusWriteSingleRegister(99, 1, 1, 120))
	// Foreign peer reads registers after the write (flow evidence).
	s.tcp(macForeign, macController, simForeignIP, 50011, simControllerIP, 502, pcapdb.TCPFlagPSH|pcapdb.TCPFlagACK,
		buildModbusReadRequest(100, 1, 3, 0, 5))
	s.tcp(macController, macForeign, simControllerIP, 502, simForeignIP, 50011, pcapdb.TCPFlagPSH|pcapdb.TCPFlagACK,
		buildModbusReadResponse(100, 1, 3, []uint16{120, 120, 2, 1, 1}))
	// Management UI access from the foreign device.
	s.tcp(macForeign, macController, simForeignIP, 50012, simControllerIP, 443, pcapdb.TCPFlagPSH|pcapdb.TCPFlagACK,
		buildTLSClientHello("storeview-ak-sm-800.filiale.local"))
	s.tcp(macForeign, macController, simForeignIP, 50013, simControllerIP, 443, pcapdb.TCPFlagPSH|pcapdb.TCPFlagACK,
		buildHTTPRequest("POST", "/xml.cgi", "storeview-ak-sm-800.filiale.local", "curl/8"))
	// BACnet WriteProperty request (observed-only).
	s.udp(macForeign, macController, simForeignIP, 47808, simControllerIP, 47808,
		buildBACnetWriteProperty(0, 1, 85))
	// BACnet I-Am of a new device.
	s.udp(macController, macForeign, simControllerIP, 47808, simBroadcastIP, 47808, buildBACnetIAm(2002, 5))
}

// appendManagementUIAttackFrames is the documented 2026 entry path: a foreign
// device talks to the supervisor UI outside the maintenance window.
func appendManagementUIAttackFrames(s *frameSeq) {
	s.tcp(macForeign, macController, simForeignIP, 50020, simControllerIP, 443, pcapdb.TCPFlagPSH|pcapdb.TCPFlagACK,
		buildTLSClientHello("storeview-ak-sm-800.filiale.local"))
	s.tcp(macForeign, macController, simForeignIP, 50021, simControllerIP, 443, pcapdb.TCPFlagPSH|pcapdb.TCPFlagACK,
		buildHTTPRequest("POST", "/xml.cgi", "storeview-ak-sm-800.filiale.local", "curl/8"))
	s.tcp(macForeign, macController, simForeignIP, 50022, simControllerIP, 443, pcapdb.TCPFlagPSH|pcapdb.TCPFlagACK,
		buildHTTPRequest("GET", "/", "storeview-ak-sm-800.filiale.local", "curl/8"))
	s.tcp(macController, macForeign, simControllerIP, 443, simForeignIP, 50022, pcapdb.TCPFlagPSH|pcapdb.TCPFlagACK,
		buildHTTPResponse(200, "OK", "StoreView"))
}

// sortedScenarioNames is used by tests for stable iteration.
func sortedScenarioNames() []string {
	names := []string{"normal", "angriff", "angriff-management-ui"}
	sort.Strings(names)
	return names
}
