//go:build linux

package rawsock

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
)

// ErrPermissionDenied indicates missing CAP_NET_RAW or root for SOCK_RAW.
var ErrPermissionDenied = errors.New("raw ICMP socket permission denied")

// Socket wraps a Linux SOCK_RAW IPPROTO_ICMP descriptor.
type Socket struct {
	fileDescriptor int
}

// Open creates an ICMP raw socket used to send probes and read error replies.
func Open() (*Socket, error) {
	fileDescriptor, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		if errors.Is(err, syscall.EPERM) {
			programName := os.Args[0]
			return nil, fmt.Errorf("%w: open SOCK_RAW IPPROTO_ICMP (try: sudo %s … or sudo setcap cap_net_raw+ep %s)", ErrPermissionDenied, programName, programName)
		}
		return nil, fmt.Errorf("socket: %w", err)
	}
	return &Socket{fileDescriptor: fileDescriptor}, nil
}

// Close releases the raw socket.
func (socket *Socket) Close() error {
	return syscall.Close(socket.fileDescriptor)
}

// SetTTL applies IP_TTL for the next outbound probe via setsockopt.
func (socket *Socket) SetTTL(timeToLive int) error {
	if timeToLive < 1 || timeToLive > 255 {
		return fmt.Errorf("ttl out of range: %d", timeToLive)
	}
	return syscall.SetsockoptInt(socket.fileDescriptor, syscall.IPPROTO_IP, syscall.IP_TTL, timeToLive)
}

// SetReadTimeout configures SO_RCVTIMEO for inbound ICMP messages.
func (socket *Socket) SetReadTimeout(timeout time.Duration) error {
	if timeout <= 0 {
		return fmt.Errorf("timeout must be positive")
	}
	timeValue := syscall.NsecToTimeval(timeout.Nanoseconds())
	return syscall.SetsockoptTimeval(socket.fileDescriptor, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &timeValue)
}

// SendTo writes a fully formed ICMP message to the destination IPv4 address.
func (socket *Socket) SendTo(destination net.IP, icmpMessage []byte) error {
	destinationIPv4 := destination.To4()
	if destinationIPv4 == nil {
		return fmt.Errorf("destination is not IPv4: %s", destination)
	}
	sockaddr := &syscall.SockaddrInet4{}
	copy(sockaddr.Addr[:], destinationIPv4)
	return syscall.Sendto(socket.fileDescriptor, icmpMessage, 0, sockaddr)
}

// RecvFrom reads one datagram including the IPv4 header prefix.
func (socket *Socket) RecvFrom(buffer []byte) (int, net.IP, error) {
	byteCount, sockaddr, err := syscall.Recvfrom(socket.fileDescriptor, buffer, 0)
	if err != nil {
		return 0, nil, err
	}
	inet4, ok := sockaddr.(*syscall.SockaddrInet4)
	if !ok {
		return byteCount, nil, nil
	}
	sourceAddress := net.IP(append([]byte(nil), inet4.Addr[:]...))
	return byteCount, sourceAddress, nil
}
