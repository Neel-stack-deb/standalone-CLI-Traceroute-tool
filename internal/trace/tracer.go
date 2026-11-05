package trace

import (
	"context"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/Neel-stack-deb/standalone-CLI-Traceroute-tool/internal/enrich"
	"github.com/Neel-stack-deb/standalone-CLI-Traceroute-tool/internal/icmpproto"
	"github.com/Neel-stack-deb/standalone-CLI-Traceroute-tool/internal/rawsock"
)

// Config controls traceroute probing behavior.
type Config struct {
	Target       string
	MaxHops      int
	ProbeTimeout time.Duration
	ProbesPerHop int
}

// HopReport is one rendered table row of trace data.
type HopReport struct {
	Number       int
	Address      net.IP
	Hostname     string
	ASN          string
	Organization string
	MinRTTMs     float64
	AvgRTTMs     float64
	MaxRTTMs     float64
	Responded    bool
	ReachedDest  bool
}

// Run executes ICMP-based traceroute using raw sockets and manual parsing.
func Run(ctx context.Context, config Config) (net.IP, []HopReport, error) {
	if err := validateConfig(config); err != nil {
		return nil, nil, err
	}

	destination, err := resolveIPv4(config.Target)
	if err != nil {
		return nil, nil, err
	}

	socket, err := rawsock.Open()
	if err != nil {
		return nil, nil, err
	}
	defer socket.Close()

	identifier := uint16(os.Getpid() & 0xffff)
	sequenceNumber := uint16(1)
	payload := make([]byte, icmpproto.DefaultPayloadLen)
	for index := range payload {
		payload[index] = byte('A' + (index % 26))
	}

	receiveBuffer := make([]byte, 1500)
	var reports []HopReport

	for hopNumber := 1; hopNumber <= config.MaxHops; hopNumber++ {
		if err := ctx.Err(); err != nil {
			return destination, reports, err
		}
		if err := socket.SetTTL(hopNumber); err != nil {
			return destination, reports, fmt.Errorf("set ttl %d: %w", hopNumber, err)
		}

		var roundTripSamples []time.Duration
		var hopAddress net.IP
		reachedDestination := false

		for probeIndex := 0; probeIndex < config.ProbesPerHop; probeIndex++ {
			message := icmpproto.MarshalEchoRequest(identifier, sequenceNumber, payload)
			sendTime := time.Now()
			if err := socket.SendTo(destination, message); err != nil {
				return destination, reports, fmt.Errorf("send probe hop=%d seq=%d: %w", hopNumber, sequenceNumber, err)
			}

			match, sample, waitErr := waitForReply(ctx, socket, receiveBuffer, identifier, sequenceNumber, destination, config.ProbeTimeout, sendTime)
			sequenceNumber++
			if waitErr != nil {
				continue
			}
			if sample > 0 {
				roundTripSamples = append(roundTripSamples, sample)
			}
			if hopAddress == nil {
				hopAddress = match.Responder
			}
			if match.Reached {
				reachedDestination = true
			}
		}

		report := buildHopReport(ctx, hopNumber, hopAddress, roundTripSamples, reachedDestination)
		reports = append(reports, report)
		if reachedDestination {
			break
		}
	}

	return destination, reports, nil
}

func validateConfig(config Config) error {
	if config.Target == "" {
		return fmt.Errorf("target host is required")
	}
	if config.MaxHops < 1 {
		return fmt.Errorf("max hops must be at least 1")
	}
	if config.ProbesPerHop < 1 {
		return fmt.Errorf("probes per hop must be at least 1")
	}
	if config.ProbeTimeout <= 0 {
		return fmt.Errorf("probe timeout must be positive")
	}
	return nil
}

func resolveIPv4(host string) (net.IP, error) {
	lookupContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupIPAddr(lookupContext, host)
	if err != nil {
		return nil, fmt.Errorf("resolve %q: %w", host, err)
	}
	for _, address := range addresses {
		if ipv4 := address.IP.To4(); ipv4 != nil {
			return ipv4, nil
		}
	}
	return nil, fmt.Errorf("no IPv4 address found for %q", host)
}

func waitForReply(
	parent context.Context,
	socket *rawsock.Socket,
	receiveBuffer []byte,
	identifier uint16,
	sequenceNumber uint16,
	destination net.IP,
	probeTimeout time.Duration,
	sendTime time.Time,
) (icmpproto.ProbeMatch, time.Duration, error) {
	deadline := time.Now().Add(probeTimeout)
	for {
		if err := parent.Err(); err != nil {
			return icmpproto.ProbeMatch{}, 0, err
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return icmpproto.ProbeMatch{}, 0, fmt.Errorf("probe timeout")
		}
		if err := socket.SetReadTimeout(remaining); err != nil {
			return icmpproto.ProbeMatch{}, 0, err
		}
		byteCount, sourceAddress, err := socket.RecvFrom(receiveBuffer)
		if err != nil {
			if errno, ok := err.(syscall.Errno); ok && (errno == syscall.EAGAIN || errno == syscall.EWOULDBLOCK) {
				return icmpproto.ProbeMatch{}, 0, fmt.Errorf("probe timeout")
			}
			continue
		}
		match, matched := icmpproto.MatchInbound(receiveBuffer[:byteCount], identifier, sequenceNumber, destination)
		if !matched {
			continue
		}
		if sourceAddress != nil && sourceAddress.To4() != nil {
			match.Responder = sourceAddress.To4()
		}
		if !isPlausibleHopAddress(match.Responder) {
			continue
		}
		return match, time.Since(sendTime), nil
	}
}

func isPlausibleHopAddress(ipAddress net.IP) bool {
	if ipAddress == nil {
		return false
	}
	ipv4 := ipAddress.To4()
	if ipv4 == nil {
		return false
	}
	if ipv4.IsMulticast() || ipv4.IsLoopback() || ipv4.IsUnspecified() {
		return false
	}
	firstOctet := ipv4[0]
	if firstOctet >= 240 {
		return false
	}
	return true
}

func buildHopReport(parent context.Context, hopNumber int, hopAddress net.IP, samples []time.Duration, reached bool) HopReport {
	report := HopReport{
		Number:      hopNumber,
		Address:     hopAddress,
		Responded:   len(samples) > 0,
		ReachedDest: reached,
	}
	if len(samples) == 0 {
		return report
	}
	minMs, avgMs, maxMs := summarizeRTT(samples)
	report.MinRTTMs = minMs
	report.AvgRTTMs = avgMs
	report.MaxRTTMs = maxMs

	metadata := enrich.LookupHostMetadata(parent, hopAddress)
	report.Hostname = metadata.Hostname
	report.ASN = metadata.ASN
	report.Organization = metadata.Organization
	return report
}

func summarizeRTT(samples []time.Duration) (float64, float64, float64) {
	minDuration := samples[0]
	maxDuration := samples[0]
	var total time.Duration
	for _, sample := range samples {
		if sample < minDuration {
			minDuration = sample
		}
		if sample > maxDuration {
			maxDuration = sample
		}
		total += sample
	}
	count := float64(len(samples))
	return toMilliseconds(minDuration), toMilliseconds(total) / count, toMilliseconds(maxDuration)
}

func toMilliseconds(duration time.Duration) float64 {
	return float64(duration.Microseconds()) / 1000.0
}
