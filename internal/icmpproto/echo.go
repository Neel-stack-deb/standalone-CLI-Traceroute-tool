package icmpproto

import (
	"encoding/binary"
	"fmt"
	"net"
)

// MarshalEchoRequest builds a type-8 ICMP Echo Request with checksum filled in.
func MarshalEchoRequest(identifier, sequence uint16, payload []byte) []byte {
	message := make([]byte, HeaderLen+len(payload))
	message[0] = TypeEchoRequest
	message[1] = 0
	binary.BigEndian.PutUint16(message[4:6], identifier)
	binary.BigEndian.PutUint16(message[6:8], sequence)
	copy(message[HeaderLen:], payload)
	checksum := OnesComplementChecksum(message)
	binary.BigEndian.PutUint16(message[2:4], checksum)
	return message
}

// ProbeMatch reports whether an inbound datagram answers a probe we sent.
type ProbeMatch struct {
	Responder net.IP
	Reached   bool
}

// MatchInbound parses a raw IPv4 datagram (IP header + ICMP) and matches identifier/sequence.
func MatchInbound(datagram []byte, identifier, sequence uint16, destination net.IP) (ProbeMatch, bool) {
	if len(datagram) < 20 {
		return ProbeMatch{}, false
	}
	headerLength := int(datagram[0]&0x0f) * 4
	if headerLength < 20 || len(datagram) < headerLength+HeaderLen {
		return ProbeMatch{}, false
	}

	responder := net.IP(append([]byte(nil), datagram[12:16]...))
	icmpBytes := datagram[headerLength:]
	messageType := icmpBytes[0]

	switch messageType {
	case TypeEchoReply:
		if len(icmpBytes) < HeaderLen {
			return ProbeMatch{}, false
		}
		replyID := binary.BigEndian.Uint16(icmpBytes[4:6])
		replySeq := binary.BigEndian.Uint16(icmpBytes[6:8])
		if replyID != identifier || replySeq != sequence {
			return ProbeMatch{}, false
		}
		reached := responder.Equal(destination)
		return ProbeMatch{Responder: responder, Reached: reached}, true

	case TypeTimeExceeded:
		return matchEmbeddedEcho(icmpBytes, identifier, sequence, responder)

	default:
		return ProbeMatch{}, false
	}
}

func matchEmbeddedEcho(icmpBytes []byte, identifier, sequence uint16, responder net.IP) (ProbeMatch, bool) {
	// Time exceeded places the original IP datagram after an 8-byte ICMP header.
	if len(icmpBytes) < HeaderLen+20 {
		return ProbeMatch{}, false
	}
	embedded := icmpBytes[HeaderLen:]
	embeddedHeaderLen := int(embedded[0]&0x0f) * 4
	if embeddedHeaderLen < 20 || len(embedded) < embeddedHeaderLen+HeaderLen {
		return ProbeMatch{}, false
	}
	embeddedICMP := embedded[embeddedHeaderLen:]
	if embeddedICMP[0] != TypeEchoRequest {
		return ProbeMatch{}, false
	}
	embeddedID := binary.BigEndian.Uint16(embeddedICMP[4:6])
	embeddedSeq := binary.BigEndian.Uint16(embeddedICMP[6:8])
	if embeddedID != identifier || embeddedSeq != sequence {
		return ProbeMatch{}, false
	}
	return ProbeMatch{Responder: responder, Reached: false}, true
}

// ValidateChecksum recomputes the ICMP checksum for debugging and tests.
func ValidateChecksum(icmpBytes []byte) error {
	if len(icmpBytes) < HeaderLen {
		return fmt.Errorf("icmp message too short")
	}
	stored := binary.BigEndian.Uint16(icmpBytes[2:4])
	copyChecksum := make([]byte, len(icmpBytes))
	copy(copyChecksum, icmpBytes)
	binary.BigEndian.PutUint16(copyChecksum[2:4], 0)
	computed := OnesComplementChecksum(copyChecksum)
	if stored != computed {
		return fmt.Errorf("checksum mismatch stored=%#x computed=%#x", stored, computed)
	}
	return nil
}
