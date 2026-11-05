//go:build !linux

package rawsock

import (
	"errors"
	"net"
	"time"
)

var ErrPermissionDenied = errors.New("raw ICMP sockets are only implemented on Linux")

type Socket struct{}

func Open() (*Socket, error) {
	return nil, errors.New("raw ICMP traceroute requires Linux")
}

func (socket *Socket) Close() error { return nil }

func (socket *Socket) SetTTL(timeToLive int) error { return errors.New("unsupported platform") }

func (socket *Socket) SetReadTimeout(timeout time.Duration) error { return errors.New("unsupported platform") }

func (socket *Socket) SendTo(destination net.IP, icmpMessage []byte) error {
	return errors.New("unsupported platform")
}

func (socket *Socket) RecvFrom(buffer []byte) (int, net.IP, error) {
	return 0, nil, errors.New("unsupported platform")
}
