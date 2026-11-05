package icmpproto

import (
	"encoding/binary"
	"testing"
)

func TestOnesComplementChecksumRFC1071Example(t *testing.T) {
	data := []byte("123456789")
	sum := OnesComplementChecksum(data)
	if sum != 0xdd2f {
		t.Fatalf("unexpected checksum: got %#x want %#x", sum, 0xdd2f)
	}
}

func TestMarshalEchoRequestChecksumValid(t *testing.T) {
	payload := make([]byte, DefaultPayloadLen)
	for index := range payload {
		payload[index] = byte(index)
	}
	message := MarshalEchoRequest(0x1234, 0x0001, payload)
	if err := ValidateChecksum(message); err != nil {
		t.Fatalf("invalid echo checksum: %v", err)
	}
	if message[0] != TypeEchoRequest {
		t.Fatalf("expected echo request type")
	}
	if binary.BigEndian.Uint16(message[4:6]) != 0x1234 {
		t.Fatalf("identifier not preserved")
	}
}
