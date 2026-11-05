package icmpproto

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestMatchInboundEchoReply(t *testing.T) {
	destination := net.IPv4(8, 8, 8, 8).To4()
	identifier := uint16(0xBEEF)
	sequence := uint16(42)

	echoReply := MarshalEchoRequest(identifier, sequence, []byte("payload-bytes-for-test"))
	echoReply[0] = TypeEchoReply
	binary.BigEndian.PutUint16(echoReply[2:4], 0)
	binary.BigEndian.PutUint16(echoReply[2:4], OnesComplementChecksum(echoReply))

	datagram := wrapIPv4(net.IPv4(8, 8, 8, 8), net.IPv4(10, 0, 0, 5), echoReply)
	match, ok := MatchInbound(datagram, identifier, sequence, destination)
	if !ok {
		t.Fatal("expected echo reply match")
	}
	if !match.Reached {
		t.Fatal("expected destination reached")
	}
}

func TestMatchInboundTimeExceeded(t *testing.T) {
	destination := net.IPv4(1, 1, 1, 1).To4()
	identifier := uint16(0xABCD)
	sequence := uint16(7)
	originalEcho := MarshalEchoRequest(identifier, sequence, []byte("probe"))

	embeddedIP := wrapIPv4(net.IPv4(10, 1, 0, 1), destination, originalEcho)
	timeExceededBody := append([]byte{TypeTimeExceeded, 0, 0, 0, 0, 0, 0, 0}, embeddedIP...)
	binary.BigEndian.PutUint16(timeExceededBody[2:4], OnesComplementChecksum(timeExceededBody))

	router := net.IPv4(192, 0, 2, 1)
	datagram := wrapIPv4(router, net.IPv4(10, 1, 0, 2), timeExceededBody)

	match, ok := MatchInbound(datagram, identifier, sequence, destination)
	if !ok {
		t.Fatal("expected time exceeded match")
	}
	if match.Reached {
		t.Fatal("did not expect destination reached")
	}
	if !match.Responder.Equal(router) {
		t.Fatalf("responder=%v want=%v", match.Responder, router)
	}
}

func wrapIPv4(source, destination net.IP, icmpMessage []byte) []byte {
	header := make([]byte, 20)
	header[0] = 0x45
	binary.BigEndian.PutUint16(header[2:4], uint16(20+len(icmpMessage)))
	header[8] = 64
	header[9] = 1
	copy(header[12:16], source.To4())
	copy(header[16:20], destination.To4())
	return append(header, icmpMessage...)
}
