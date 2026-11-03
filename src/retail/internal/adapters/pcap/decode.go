// Frame decoding: Ethernet/VLAN/IPv4/TCP/UDP into passive Packet values.
package pcap

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"time"
)

const (
	etherHeaderLen = 14
	vlanHeaderLen  = 4
	ipv4MinHeader  = 20
	tcpMinHeader   = 20
	udpHeaderLen   = 8
)

// Decode turns one pcap record into a Packet. Unsupported-but-valid frames
// (IPv6, ARP, non-TCP/UDP) return a Packet with empty addresses and
// ErrUnsupportedIP / nil ports; callers count them as "other traffic" instead
// of a parser error.
func Decode(linkType uint32, raw []byte, ts time.Time) (Packet, error) {
	pkt := Packet{Timestamp: ts, LinkType: linkType}
	switch linkType {
	case LinkTypeEthernet:
		payload, err := decodeEthernet(raw, &pkt)
		if err != nil {
			return pkt, err
		}
		return decodeIPv4(payload, &pkt)
	case LinkTypeRawIPv4:
		return decodeIPv4(raw, &pkt)
	default:
		return pkt, fmt.Errorf("%w: %d", ErrUnsupportedLink, linkType)
	}
}

// decodeEthernet parses the L2 header (with one optional VLAN tag) and returns
// the L3 payload.
func decodeEthernet(raw []byte, pkt *Packet) ([]byte, error) {
	if len(raw) < etherHeaderLen {
		return nil, fmt.Errorf("%w: ethernet header", ErrShortFrame)
	}
	copy(pkt.DstMAC[:], raw[0:6])
	copy(pkt.SrcMAC[:], raw[6:12])
	etherType := binary.BigEndian.Uint16(raw[12:14])
	offset := etherHeaderLen
	if etherType == etherTypeVLAN || etherType == etherTypeQinQ {
		if len(raw) < offset+vlanHeaderLen {
			return nil, fmt.Errorf("%w: vlan header", ErrShortFrame)
		}
		etherType = binary.BigEndian.Uint16(raw[offset+2 : offset+4])
		offset += vlanHeaderLen
	}
	switch etherType {
	case etherTypeIPv4:
		return raw[offset:], nil
	case etherTypeIPv6:
		return nil, ErrUnsupportedIP
	case etherTypeARP:
		pkt.Bytes = len(raw)
		return nil, fmt.Errorf("%w: arp", ErrNotIPv4)
	default:
		pkt.Bytes = len(raw)
		return nil, fmt.Errorf("%w: ethertype 0x%04x", ErrNotIPv4, etherType)
	}
}

// decodeIPv4 parses the IPv4 header and dispatches to TCP/UDP.
func decodeIPv4(raw []byte, pkt *Packet) (Packet, error) {
	if len(raw) < ipv4MinHeader {
		return *pkt, fmt.Errorf("%w: ipv4 header", ErrShortFrame)
	}
	if raw[0]>>4 != 4 {
		return *pkt, ErrUnsupportedIP
	}
	ihl := int(raw[0]&0x0f) * 4
	if ihl < ipv4MinHeader || ihl > len(raw) {
		return *pkt, fmt.Errorf("%w: ipv4 ihl %d", ErrShortFrame, ihl)
	}
	totalLen := int(binary.BigEndian.Uint16(raw[2:4]))
	if totalLen < ihl {
		return *pkt, fmt.Errorf("%w: ipv4 total length %d", ErrShortFrame, totalLen)
	}
	// Truncated captures are valid input; clamp instead of rejecting.
	l3 := raw
	if totalLen < len(raw) {
		l3 = raw[:totalLen]
	}
	src, ok := netip.AddrFromSlice(l3[12:16])
	if !ok {
		return *pkt, fmt.Errorf("%w: source address", ErrShortFrame)
	}
	dst, ok := netip.AddrFromSlice(l3[16:20])
	if !ok {
		return *pkt, fmt.Errorf("%w: destination address", ErrShortFrame)
	}
	pkt.SrcIP = src.Unmap().String()
	pkt.DstIP = dst.Unmap().String()
	pkt.Protocol = l3[9]

	// Fragmented packets (offset != 0) do not carry a usable L4 header.
	flagsFrag := binary.BigEndian.Uint16(l3[6:8])
	if flagsFrag&0x1fff != 0 {
		pkt.Bytes = len(l3) - ihl
		return *pkt, nil
	}
	segment := l3[ihl:]
	pkt.Bytes = len(segment)
	switch pkt.Protocol {
	case ipProtoTCP:
		if len(segment) < tcpMinHeader {
			return *pkt, fmt.Errorf("%w: tcp header", ErrShortFrame)
		}
		dataOffset := int(segment[12]>>4) * 4
		if dataOffset < tcpMinHeader || dataOffset > len(segment) {
			return *pkt, fmt.Errorf("%w: tcp data offset %d", ErrShortFrame, dataOffset)
		}
		pkt.SrcPort = binary.BigEndian.Uint16(segment[0:2])
		pkt.DstPort = binary.BigEndian.Uint16(segment[2:4])
		pkt.TCPFlags = segment[13]
		pkt.Payload = segment[dataOffset:]
		return *pkt, nil
	case ipProtoUDP:
		if len(segment) < udpHeaderLen {
			return *pkt, fmt.Errorf("%w: udp header", ErrShortFrame)
		}
		pkt.SrcPort = binary.BigEndian.Uint16(segment[0:2])
		pkt.DstPort = binary.BigEndian.Uint16(segment[2:4])
		udpLen := int(binary.BigEndian.Uint16(segment[4:6]))
		if udpLen < udpHeaderLen || udpLen > len(segment) {
			return *pkt, fmt.Errorf("%w: udp length %d", ErrShortFrame, udpLen)
		}
		pkt.Payload = segment[udpHeaderLen:udpLen]
		pkt.Bytes = udpLen
		return *pkt, nil
	default:
		// ICMP and other protocols are valid capture content, not parser errors.
		return *pkt, nil
	}
}
