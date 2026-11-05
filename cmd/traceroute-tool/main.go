package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/Neel-stack-deb/standalone-CLI-Traceroute-tool/internal/trace"
)

func main() {
	maxHops := flag.Int("m", 30, "maximum number of hops")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [-m max-hops] host\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	host := flag.Arg(0)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	hops, err := trace.Run(ctx, host, *maxHops)
	if err != nil {
		fmt.Fprintf(os.Stderr, "traceroute-tool: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("traceroute to %s (%d hops max)\n", host, *maxHops)
	for _, h := range hops {
		fmt.Printf("%2d  %-40s  %s\n", h.Number, h.Host, h.RTT)
	}
}
