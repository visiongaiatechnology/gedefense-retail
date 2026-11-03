// Deterministic synthetic frame builders for the PCAP scenarios. These are
// SIMULATOR-ONLY fixtures (attack traffic for tests), never used by an adapter.
package main

import (
	"encoding/binary"
	"math"

	pcapdb "github.com/visiongaiatechnology/gedefense/retail/internal/adapters/pcap"
)

// Simulated MAC addresses (locally administered ranges, documentation only).
var (
	macPanel      = [6]byte{0x02, 0x00, 0x00, 0x00, 0x50, 0x20}
	macController = [6]byte{0x02, 0x00, 0x00, 0x00, 0x50, 0x10}
	macForeign    = [6]byte{0x02, 0x00, 0x00, 0x00, 0x99, 0x50}
	macBroker     = [6]byte{0x02, 0x00, 0x00, 0x00, 0x50, 0x40}
)

func endpoint(ip string, port uint16) pcapdb.Endpoint {
	return pcapdb.Endpoint{IP: ip, Port: port}
}

// buildModbusReadRequest builds an FC3/FC4 request PDU (read-only).
func buildModbusReadRequest(transactionID uint16, unitID uint8, function uint8, address, quantity uint16) []byte {
	pdu := []byte{function, byte(address >> 8), byte(address), byte(quantity >> 8), byte(quantity)}
	return mbapFrame(transactionID, unitID, pdu)
}

// buildModbusReadResponse builds an FC3/FC4 response.
func buildModbusReadResponse(transactionID uint16, unitID uint8, function uint8, values []uint16) []byte {
	pdu := []byte{function, byte(2 * len(values))}
	for _, value := range values {
		pdu = append(pdu, byte(value>>8), byte(value))
	}
	return mbapFrame(transactionID, unitID, pdu)
}

// buildModbusWriteSingleRegister builds a synthetic FC6 frame. It exists ONLY
// in the simulator to generate attack fixtures for the passive tap test.
func buildModbusWriteSingleRegister(transactionID uint16, unitID uint8, address, value uint16) []byte {
	pdu := []byte{6, byte(address >> 8), byte(address), byte(value >> 8), byte(value)}
	return mbapFrame(transactionID, unitID, pdu)
}

func mbapFrame(transactionID uint16, unitID uint8, pdu []byte) []byte {
	frame := make([]byte, 7+len(pdu))
	binary.BigEndian.PutUint16(frame[0:2], transactionID)
	binary.BigEndian.PutUint16(frame[2:4], 0)
	binary.BigEndian.PutUint16(frame[4:6], uint16(1+len(pdu)))
	frame[6] = unitID
	copy(frame[7:], pdu)
	return frame
}

// buildMQTTConnect builds a minimal MQTT 3.1.1 CONNECT (clean session).
func buildMQTTConnect(clientID string) []byte {
	body := []byte{0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x02, 0x00, 0x1e}
	body = append(body, byte(len(clientID)>>8), byte(len(clientID)))
	body = append(body, clientID...)
	return append([]byte{0x10, byte(len(body))}, body...)
}

// buildMQTTSubscribe builds a QoS0 SUBSCRIBE for one topic.
func buildMQTTSubscribe(packetID uint16, topic string) []byte {
	body := []byte{byte(packetID >> 8), byte(packetID), byte(len(topic) >> 8), byte(len(topic))}
	body = append(body, topic...)
	body = append(body, 0x00)
	return append([]byte{0x82, byte(len(body))}, body...)
}

// buildMQTTPublish builds a QoS0 PUBLISH (broker -> client direction).
func buildMQTTPublish(topic string, payload []byte) []byte {
	body := []byte{byte(len(topic) >> 8), byte(len(topic))}
	body = append(body, topic...)
	body = append(body, payload...)
	return append([]byte{0x30, byte(len(body))}, body...)
}

// buildBACnetIAm builds a BVLC/NPDU/APDU I-Am for the given device instance.
func buildBACnetIAm(deviceInstance uint32, vendorID uint16) []byte {
	objectID := uint32(8)<<22 | (deviceInstance & 0x3fffff)
	body := []byte{0x10, 0x00, 0xC4}
	body = appendUint32(body, objectID)
	body = append(body, 0x22, 0x01, 0xE0) // max APDU 480
	body = append(body, 0x91, 0x03)       // segmentation: no segmentation
	body = append(body, 0x22, byte(vendorID>>8), byte(vendorID))
	return bvlcWrap(body)
}

// buildBACnetReadPropertyAck builds a ReadProperty-ACK with a REAL present-value.
func buildBACnetReadPropertyAck(objectType uint8, instance uint32, property uint8, value float32) []byte {
	objectID := uint32(objectType)<<22 | (instance & 0x3fffff)
	body := []byte{0x30, 0x01, 0x0C, 0x04}
	body = appendUint32(body, objectID)
	body = append(body, 0x11, property)
	body = append(body, 0x44)
	body = appendUint32(body, float32Bits(value))
	return bvlcWrap(body)
}

// buildBACnetWriteProperty builds a synthetic WriteProperty confirmed request
// (observed-only evidence for the passive decoder).
func buildBACnetWriteProperty(objectType uint8, instance uint32, property uint8) []byte {
	objectID := uint32(objectType)<<22 | (instance & 0x3fffff)
	body := []byte{0x00, 0x05, 0x02, 0x0F, 0x04}
	body = appendUint32(body, objectID)
	body = append(body, 0x11, property, 0x44)
	body = appendUint32(body, float32Bits(12.0))
	return bvlcWrap(body)
}

func bvlcWrap(apdu []byte) []byte {
	npdu := append([]byte{0x01, 0x00}, apdu...)
	frame := []byte{0x81, 0x0A, 0x00, 0x00}
	binary.BigEndian.PutUint16(frame[2:4], uint16(4+len(npdu)))
	return append(frame, npdu...)
}

// buildHTTPRequest builds a plaintext HTTP request (metadata only).
func buildHTTPRequest(method, path, host, userAgent string) []byte {
	request := method + " " + path + " HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: " + userAgent +
		"\r\nAccept: */*\r\nContent-Length: 0\r\n\r\n"
	return []byte(request)
}

// buildHTTPResponse builds a plaintext HTTP response with a Server header.
func buildHTTPResponse(status int, reason, server string) []byte {
	return []byte("HTTP/1.1 " + itoa(status) + " " + reason + "\r\nServer: " + server +
		"\r\nContent-Type: text/html\r\nContent-Length: 0\r\n\r\n")
}

// buildTLSClientHello builds a minimal TLS 1.2 ClientHello carrying only SNI.
func buildTLSClientHello(sni string) []byte {
	hello := make([]byte, 0, 128)
	hello = append(hello, 0x03, 0x03)          // client version TLS 1.2
	hello = append(hello, make([]byte, 32)...) // random
	hello = append(hello, 0x00)                // session id length
	hello = append(hello, 0x00, 0x02, 0x00, 0x2f)
	hello = append(hello, 0x01, 0x00) // compression methods: null
	extensions := make([]byte, 0, 64)
	serverName := []byte(sni)
	entry := []byte{0x00, byte(len(serverName) >> 8), byte(len(serverName))}
	entry = append(entry, serverName...)
	list := []byte{byte(len(entry) >> 8), byte(len(entry))}
	list = append(list, entry...)
	ext := []byte{0x00, 0x00, byte(len(list) >> 8), byte(len(list))}
	ext = append(ext, list...)
	extensions = append([]byte{byte(len(ext) >> 8), byte(len(ext))}, ext...)
	hello = append(hello, extensions...)

	handshake := []byte{0x01, byte(len(hello) >> 16), byte(len(hello) >> 8), byte(len(hello))}
	handshake = append(handshake, hello...)
	record := []byte{0x16, 0x03, 0x01, byte(len(handshake) >> 8), byte(len(handshake))}
	return append(record, handshake...)
}

func appendUint32(dst []byte, value uint32) []byte {
	return append(dst, byte(value>>24), byte(value>>16), byte(value>>8), byte(value))
}

func float32Bits(value float32) uint32 {
	return math.Float32bits(value)
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	digits := [4]byte{}
	n := 0
	for v := value; v > 0; v /= 10 {
		digits[n] = byte('0' + v%10)
		n++
	}
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = digits[n-1-i]
	}
	return string(out)
}
