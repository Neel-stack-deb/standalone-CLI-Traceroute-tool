package icmpproto

import "encoding/binary"

// OnesComplementChecksum implements RFC 1071 for the ICMP message body.
func OnesComplementChecksum(message []byte) uint16 {
	var accumulator uint32
	for offset := 0; offset+1 < len(message); offset += 2 {
		accumulator += uint32(binary.BigEndian.Uint16(message[offset : offset+2]))
	}
	if len(message)%2 == 1 {
		accumulator += uint32(message[len(message)-1]) << 8
	}
	for accumulator>>16 != 0 {
		accumulator = (accumulator & 0xffff) + (accumulator >> 16)
	}
	return ^uint16(accumulator)
}
