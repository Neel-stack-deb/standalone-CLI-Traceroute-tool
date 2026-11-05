package trace

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// Hop is one line of traceroute-style output.
type Hop struct {
	Number int
	Host   string
	RTT    string
}

var hopLine = regexp.MustCompile(`^\s*(\d+):\s+(.+?)\s*([\d.]+\s*ms)?\s*$`)

// Run traces the route to host using tracepath (unprivileged on Linux).
func Run(ctx context.Context, host string, maxHops int) ([]Hop, error) {
	if maxHops < 1 {
		return nil, fmt.Errorf("max hops must be at least 1")
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return nil, fmt.Errorf("host is required")
	}

	ctx, cancel := context.WithTimeout(ctx, time.Duration(maxHops*4+10)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "tracepath", "-m", fmt.Sprintf("%d", maxHops), host)
	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("tracepath: %w", err)
	}

	var hops []Hop
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()
		m := hopLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		var num int
		if _, err := fmt.Sscanf(m[1], "%d", &num); err != nil {
			continue
		}
		rtt := strings.TrimSpace(m[3])
		hostName := strings.TrimSpace(m[2])
		if rtt == "" {
			rtt = "*"
		}
		hops = append(hops, Hop{Number: num, Host: hostName, RTT: rtt})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(hops) == 0 {
		return nil, fmt.Errorf("no hop data from tracepath")
	}
	return hops, nil
}
