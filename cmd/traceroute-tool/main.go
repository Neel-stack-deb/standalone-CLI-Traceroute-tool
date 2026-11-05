package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/Neel-stack-deb/standalone-CLI-Traceroute-tool/internal/output"
	"github.com/Neel-stack-deb/standalone-CLI-Traceroute-tool/internal/rawsock"
	"github.com/Neel-stack-deb/standalone-CLI-Traceroute-tool/internal/trace"
)

func main() {
	maxHops := flag.Int("m", 30, "maximum hop limit (TTL)")
	timeoutSeconds := flag.Float64("w", 3.0, "per-probe timeout in seconds")
	probesPerHop := flag.Int("q", 3, "probes per hop")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [-m max-hops] [-w timeout] [-q probes] host\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	targetHost := flag.Arg(0)

	config := trace.Config{
		Target:       targetHost,
		MaxHops:      *maxHops,
		ProbeTimeout: time.Duration(*timeoutSeconds * float64(time.Second)),
		ProbesPerHop: *probesPerHop,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	destination, reports, err := trace.Run(ctx, config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "traceroute-tool: %v\n", err)
		if errors.Is(err, rawsock.ErrPermissionDenied) {
			fmt.Fprintln(os.Stderr, "\nLinux requires CAP_NET_RAW or root for SOCK_RAW IPPROTO_ICMP.")
			fmt.Fprintf(os.Stderr, "Examples:\n  sudo %s %s\n  sudo setcap cap_net_raw+ep %s\n", os.Args[0], targetHost, os.Args[0])
		}
		os.Exit(1)
	}

	output.PrintHeader(targetHost, destination, config.MaxHops, config.ProbesPerHop)
	output.PrintTable(reports)
}
