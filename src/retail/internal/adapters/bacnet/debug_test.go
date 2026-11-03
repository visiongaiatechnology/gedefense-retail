package bacnet

import (
	"fmt"
	"testing"
)

// TestDebugDecode is a developer aid kept as a regression check for the full
// decode chain (BVLC -> NPDU -> APDU).
func TestDebugDecode(t *testing.T) {
	frame := testIAmFrame(1001, 5)
	npdu, err := decodeBVLC(frame)
	if err != nil {
		t.Fatalf("bvlc: %v", err)
	}
	apdu, err := decodeNPDU(npdu)
	if err != nil {
		t.Fatalf("npdu: %v", err)
	}
	msg, err := decodeAPDU(apdu)
	if err != nil {
		t.Fatalf("apdu: %v (%s)", err, fmt.Sprint(apdu))
	}
	if msg == nil || msg.kind != msgIAm || msg.deviceInstance != 1001 {
		t.Fatalf("unexpected message: %+v", msg)
	}

	rp := testReadPropertyAckFrame(objTypeAnalogInput, 1, 85, 4.2)
	npdu, err = decodeBVLC(rp)
	if err != nil {
		t.Fatalf("bvlc rp: %v", err)
	}
	apdu, err = decodeNPDU(npdu)
	if err != nil {
		t.Fatalf("npdu rp: %v", err)
	}
	rpMsg, err := decodeAPDU(apdu)
	if err != nil {
		t.Fatalf("apdu rp: %v (apdu %v)", err, apdu)
	}
	if rpMsg == nil {
		t.Fatalf("rp message is nil (apdu %v)", apdu)
	}
	if rpMsg.kind != msgReadPropertyAck || rpMsg.property != 85 || rpMsg.objectType != objTypeAnalogInput {
		t.Fatalf("unexpected rp message: %+v", rpMsg)
	}
}
