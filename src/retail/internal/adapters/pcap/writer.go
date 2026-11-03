// PCAP writer and deterministic frame builders for fixtures and the simulator.
package pcap

import (
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/netx"
)

// Writer writes a classic little-endian, microsecond-resolution pcap file.
// Timestamps and payloads are supplied by the caller so fixtures are fully
// deterministic.
type Writer struct {
	w     io.Writer
	bo    binary.ByteOrder
	nano  bool
	count uint64
}

// NewWriter writes the 24-byte global header for Ethernet captures.
func NewWriter(w io.Writer) (*Writer, error) {
	return NewWriterLinkType(w, LinkTypeEthernet)
}

// NewWriterLinkType writes the global header for the given link type.
func NewWriterLinkType(w io.Writer, linkType uint32) (*Writer, error) {
	if w == nil {
		return nil, fmt.Errorf("pcap: nil writer")
	}
	if linkType != LinkTypeEthernet && linkType != LinkTypeRawIPv4 {
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedLink, linkType)
	}
	header := make([]byte, 24)
	binary.LittleEndian.PutUint32(header[0:4], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(header[4:6], 2)
	binary.LittleEndian.PutUint16(header[6:8], 4)
	binary.LittleEndian.PutUint32(header[16:20], 262144)
	binary.LittleEndian.PutUint32(header[20:24], linkType)
	if _, err := w.Write(header); err != nil {
		return nil, fmt.Errorf("pcap: write global header: %w", err)
	}
	return &Writer{w: w, bo: binary.LittleEndian}, nil
}

// WritePacket appends one record. Ts is truncated to microseconds.
func (w *Writer) WritePacket(ts time.Time, data []byte) error {
	if len(data) == 0 || len(data) > MaxPacketLen {
		return fmt.Errorf("%w: packet length %d", ErrBadRecord, len(data))
	}
	ts = ts.UTC()
	us := ts.Nanosecond() / 1000
	header := make([]byte, 16)
	w.bo.PutUint32(header[0:4], uint32(ts.Unix()))
	w.bo.PutUint32(header[4:8], uint32(us))
	w.bo.PutUint32(header[8:12], uint32(len(data)))
	w.bo.PutUint32(header[12:16], uint32(len(data)))
	if _, err := w.w.Write(header); err != nil {
		return fmt.Errorf("pcap: write record header: %w", err)
	}
	if _, err := w.w.Write(data); err != nil {
		return fmt.Errorf("pcap: write record data: %w", err)
	}
	w.count++
	return nil
}

// Count returns the number of records written.
func (w *Writer) Count() uint64 { return w.count }

// BuildEthernet wraps an L3 payload into an Ethernet frame.
func BuildEthernet(dstMAC, srcMAC [6]byte, etherType uint16, payload []byte) []byte {
	frame := make([]byte, etherHeaderLen+len(payload))
	copy(frame[0:6], dstMAC[:])
	copy(frame[6:12], srcMAC[:])
	binary.BigEndian.PutUint16(frame[12:14], etherType)
	copy(frame[etherHeaderLen:], payload)
	return frame
}

// BuildEthernetIPv4TCP builds a complete Ethernet/IPv4/TCP frame with valid
// header checksums.
func BuildEthernetIPv4TCP(dstMAC, srcMAC [6]byte, src, dst Endpoint, seq, ack uint32, flags uint8, payload []byte) ([]byte, error) {
	ip, err := BuildIPv4TCP(src, dst, seq, ack, flags, payload)
	if err != nil {
		return nil, err
	}
	return BuildEthernet(dstMAC, srcMAC, etherTypeIPv4, ip), nil
}

// BuildEthernetIPv4UDP builds a complete Ethernet/IPv4/UDP frame.
func BuildEthernetIPv4UDP(dstMAC, srcMAC [6]byte, src, dst Endpoint, payload []byte) ([]byte, error) {
	ip, err := BuildIPv4UDP(src, dst, payload)
	if err != nil {
		return nil, err
	}
	return BuildEthernet(dstMAC, srcMAC, etherTypeIPv4, ip), nil
}

// BuildIPv4TCP builds an IPv4/TCP packet (for raw-IPv4 link types).
func BuildIPv4TCP(src, dst Endpoint, seq, ack uint32, flags uint8, payload []byte) ([]byte, error) {
	srcAddr, dstAddr, err := endpointAddrs(src, dst)
	if err != nil {
		return nil, err
	}
	segment := buildTCPSegment(srcAddr, dstAddr, src.Port, dst.Port, seq, ack, flags, payload)
	return buildIPv4(srcAddr, dstAddr, ipProtoTCP, segment), nil
}

// BuildIPv4UDP builds an IPv4/UDP packet.
func BuildIPv4UDP(src, dst Endpoint, payload []byte) ([]byte, error) {
	srcAddr, dstAddr, err := endpointAddrs(src, dst)
	if err != nil {
		return nil, err
	}
	segment := make([]byte, udpHeaderLen+len(payload))
	binary.BigEndian.PutUint16(segment[0:2], src.Port)
	binary.BigEndian.PutUint16(segment[2:4], dst.Port)
	binary.BigEndian.PutUint16(segment[4:6], uint16(udpHeaderLen+len(payload)))
	copy(segment[udpHeaderLen:], payload)
	binary.BigEndian.PutUint16(segment[6:8], checksum(pseudoHeader(srcAddr, dstAddr, ipProtoUDP, segment), segment))
	return buildIPv4(srcAddr, dstAddr, ipProtoUDP, segment), nil
}

func endpointAddrs(src, dst Endpoint) ([4]byte, [4]byte, error) {
	var srcRaw, dstRaw [4]byte
	srcAddr, err := netx.ParseAddr(src.IP)
	if err != nil || !srcAddr.Is4() {
		return srcRaw, dstRaw, fmt.Errorf("pcap: invalid source ip %q", src.IP)
	}
	dstAddr, err := netx.ParseAddr(dst.IP)
	if err != nil || !dstAddr.Is4() {
		return srcRaw, dstRaw, fmt.Errorf("pcap: invalid destination ip %q", dst.IP)
	}
	return srcAddr.As4(), dstAddr.As4(), nil
}

func buildTCPSegment(srcIP, dstIP [4]byte, srcPort, dstPort uint16, seq, ack uint32, flags uint8, payload []byte) []byte {
	segment := make([]byte, tcpMinHeader+len(payload))
	binary.BigEndian.PutUint16(segment[0:2], srcPort)
	binary.BigEndian.PutUint16(segment[2:4], dstPort)
	binary.BigEndian.PutUint32(segment[4:8], seq)
	binary.BigEndian.PutUint32(segment[8:12], ack)
	segment[12] = byte(tcpMinHeader/4) << 4
	segment[13] = flags
	binary.BigEndian.PutUint16(segment[14:16], 8192) // window
	copy(segment[tcpMinHeader:], payload)
	binary.BigEndian.PutUint16(segment[16:18], checksum(pseudoHeader(srcIP, dstIP, ipProtoTCP, segment), segment))
	return segment
}

func buildIPv4(srcIP, dstIP [4]byte, protocol uint8, segment []byte) []byte {
	ip := make([]byte, ipv4MinHeader+len(segment))
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
	ip[8] = 64 // TTL
	ip[9] = protocol
	copy(ip[12:16], srcIP[:])
	copy(ip[16:20], dstIP[:])
	binary.BigEndian.PutUint16(ip[10:12], checksum(ip[:ipv4MinHeader], nil))
	copy(ip[ipv4MinHeader:], segment)
	return ip
}

// pseudoHeader builds the TCP/UDP checksum pseudo header.
func pseudoHeader(srcIP, dstIP [4]byte, protocol uint8, segment []byte) []byte {
	header := make([]byte, 12)
	copy(header[0:4], srcIP[:])
	copy(header[4:8], dstIP[:])
	header[9] = protocol
	binary.BigEndian.PutUint16(header[10:12], uint16(len(segment)))
	return header
}

// checksum computes the Internet checksum over the concatenation of parts.
func checksum(parts []byte, tail []byte) uint16 {
	var sum uint32
	accumulate := func(b []byte) {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
		}
		if len(b)%2 == 1 {
			sum += uint32(b[len(b)-1]) << 8
		}
	}
	accumulate(parts)
	accumulate(tail)
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
