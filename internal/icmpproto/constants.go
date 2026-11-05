package icmpproto

// ICMP message types used by this traceroute implementation (RFC 792).
const (
	TypeEchoReply          = 0
	TypeDestinationUnreach = 3
	TypeTimeExceeded       = 11
	TypeEchoRequest        = 8
)

// HeaderLen is the fixed ICMP header size in bytes: type, code, checksum, id, sequence.
const HeaderLen = 8

// DefaultPayloadLen is the data section size appended to each echo request probe.
const DefaultPayloadLen = 32
