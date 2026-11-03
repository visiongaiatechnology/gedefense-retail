// Package pcap implements an offline PCAP reader/writer and the packet decoder
// used by the PCAP collector and the simulator fixtures.
//
// Supported: classic libpcap files (microsecond and nanosecond magic, both byte
// orders), Ethernet with at most one VLAN tag, plain IPv4 links, IPv4, TCP and
// UDP. The decoder never validates checksums of captured traffic (captures may
// be truncated) and never sends a packet.
package pcap

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

// Link types supported by the reader/decoder.
const (
	LinkTypeEthernet uint32 = 1   // LINKTYPE_ETHERNET
	LinkTypeRawIPv4  uint32 = 101 // LINKTYPE_RAW (IPv4 only here)
)

// Limits that keep malformed files from causing large allocations.
const (
	MaxSnaplen   = 262144
	MaxPacketLen = 262144
)

// EtherTypes and IP protocol numbers understood by the decoder.
const (
	etherTypeIPv4 uint16 = 0x0800
	etherTypeARP  uint16 = 0x0806
	etherTypeVLAN uint16 = 0x8100
	etherTypeQinQ uint16 = 0x88A8
	etherTypeIPv6 uint16 = 0x86DD

	ipProtoICMP uint8 = 1
	ipProtoTCP  uint8 = 6
	ipProtoUDP  uint8 = 17
)

// TCP flag bits used by the writers/tests.
const (
	TCPFlagFIN uint8 = 0x01
	TCPFlagSYN uint8 = 0x02
	TCPFlagRST uint8 = 0x04
	TCPFlagPSH uint8 = 0x08
	TCPFlagACK uint8 = 0x10
)

// Errors returned by the reader and decoder.
var (
	ErrBadMagic        = errors.New("pcap: unsupported pcap magic")
	ErrTruncated       = errors.New("pcap: truncated file")
	ErrBadRecord       = errors.New("pcap: invalid record header")
	ErrUnsupportedLink = errors.New("pcap: unsupported link type")
	ErrShortFrame      = errors.New("pcap: short frame")
	ErrNotIPv4         = errors.New("pcap: not an ipv4 packet")
	ErrUnsupportedIP   = errors.New("pcap: unsupported ip version")
)

// Record is one captured frame read from a pcap file.
type Record struct {
	Timestamp time.Time
	InclLen   uint32
	OrigLen   uint32
	Data      []byte
}

// Reader reads classic pcap files sequentially.
type Reader struct {
	r          io.Reader
	byteOrder  binary.ByteOrder
	nanosecond bool
	linkType   uint32
	snaplen    uint32
	records    uint64
}

// NewReader parses the global header and returns a reader positioned at the
// first record. The caller closes the underlying reader.
func NewReader(r io.Reader) (*Reader, error) {
	if r == nil {
		return nil, fmt.Errorf("pcap: nil reader")
	}
	header := make([]byte, 24)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, fmt.Errorf("%w: global header: %v", ErrTruncated, err)
	}
	bo, nano, err := magicInfo(header[0:4])
	if err != nil {
		return nil, err
	}
	versionMajor := bo.Uint16(header[4:6])
	versionMinor := bo.Uint16(header[6:8])
	if versionMajor != 2 || versionMinor > 4 {
		return nil, fmt.Errorf("pcap: unsupported version %d.%d", versionMajor, versionMinor)
	}
	snaplen := bo.Uint32(header[16:20])
	if snaplen == 0 || snaplen > MaxSnaplen {
		return nil, fmt.Errorf("pcap: invalid snaplen %d", snaplen)
	}
	linkType := bo.Uint32(header[20:24]) & 0x0fffffff
	if linkType != LinkTypeEthernet && linkType != LinkTypeRawIPv4 {
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedLink, linkType)
	}
	return &Reader{r: r, byteOrder: bo, nanosecond: nano, linkType: linkType, snaplen: snaplen}, nil
}

// magicInfo derives the byte order and timestamp resolution from the magic.
func magicInfo(magic []byte) (binary.ByteOrder, bool, error) {
	if len(magic) < 4 {
		return nil, false, ErrTruncated
	}
	switch {
	case magic[0] == 0xa1 && magic[1] == 0xb2 && magic[2] == 0xc3 && magic[3] == 0xd4:
		return binary.BigEndian, false, nil
	case magic[0] == 0xd4 && magic[1] == 0xc3 && magic[2] == 0xb2 && magic[3] == 0xa1:
		return binary.LittleEndian, false, nil
	case magic[0] == 0xa1 && magic[1] == 0xb2 && magic[2] == 0x3c && magic[3] == 0x4d:
		return binary.BigEndian, true, nil
	case magic[0] == 0x4d && magic[1] == 0x3c && magic[2] == 0xb2 && magic[3] == 0xa1:
		return binary.LittleEndian, true, nil
	default:
		return nil, false, ErrBadMagic
	}
}

// LinkType returns the link type declared by the global header.
func (r *Reader) LinkType() uint32 { return r.linkType }

// Next reads the next record. It returns io.EOF at the end of the file.
func (r *Reader) Next() (Record, error) {
	header := make([]byte, 16)
	n, err := io.ReadFull(r.r, header)
	if err != nil {
		if n == 0 && errors.Is(err, io.EOF) {
			return Record{}, io.EOF
		}
		return Record{}, fmt.Errorf("%w: record header: %v", ErrTruncated, err)
	}
	tsSec := r.byteOrder.Uint32(header[0:4])
	tsSub := r.byteOrder.Uint32(header[4:8])
	inclLen := r.byteOrder.Uint32(header[8:12])
	origLen := r.byteOrder.Uint32(header[12:16])
	if inclLen > MaxPacketLen || inclLen > r.snaplen {
		return Record{}, fmt.Errorf("%w: incl_len %d", ErrBadRecord, inclLen)
	}
	if origLen < inclLen {
		return Record{}, fmt.Errorf("%w: orig_len %d < incl_len %d", ErrBadRecord, origLen, inclLen)
	}
	data := make([]byte, inclLen)
	if _, err := io.ReadFull(r.r, data); err != nil {
		return Record{}, fmt.Errorf("%w: packet data: %v", ErrTruncated, err)
	}
	var ts time.Time
	if r.nanosecond {
		ts = time.Unix(int64(tsSec), int64(tsSub%1e9)).UTC()
	} else {
		ts = time.Unix(int64(tsSec), int64(tsSub%1e6)*1000).UTC()
	}
	r.records++
	return Record{Timestamp: ts, InclLen: inclLen, OrigLen: origLen, Data: data}, nil
}

// Records returns how many records have been read so far.
func (r *Reader) Records() uint64 { return r.records }

// Endpoint is one side of a decoded conversation.
type Endpoint struct {
	IP   string
	Port uint16
	MAC  [6]byte
}

// Packet is the decoded passive view of one captured frame.
type Packet struct {
	Timestamp time.Time
	LinkType  uint32
	SrcMAC    [6]byte
	DstMAC    [6]byte
	SrcIP     string
	DstIP     string
	Protocol  uint8 // IP protocol number (0 for non-IP frames)
	SrcPort   uint16
	DstPort   uint16
	TCPFlags  uint8
	Payload   []byte
	// Bytes is the IPv4 total length minus the IP header (TCP/UDP segment) or
	// the raw frame length for non-IP frames.
	Bytes int
}
