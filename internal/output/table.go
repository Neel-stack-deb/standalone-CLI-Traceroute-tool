package output

import (
	"fmt"
	"net"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/Neel-stack-deb/standalone-CLI-Traceroute-tool/internal/trace"
)

// PrintHeader prints the destination banner line.
func PrintHeader(targetHost string, destination net.IP, maxHops int, probeCount int) {
	fmt.Fprintf(os.Stdout, "traceroute to %s (%s), %d hops max, %d probes per hop\n\n", targetHost, destination, maxHops, probeCount)
}

// PrintTable renders hop results in aligned columns.
func PrintTable(reports []trace.HopReport) {
	writer := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(writer, "Hop #\tRTT min/avg/max (ms)\tIP Address\tHostname / PTR\tASN & ISP")
	for _, report := range reports {
		fmt.Fprintln(writer, formatRow(report))
	}
	_ = writer.Flush()
}

func formatRow(report trace.HopReport) string {
	rttColumn := "* * *"
	if report.Responded {
		rttColumn = fmt.Sprintf("%.3f/%.3f/%.3f", report.MinRTTMs, report.AvgRTTMs, report.MaxRTTMs)
	}

	ipAddress := "*"
	if report.Address != nil {
		ipAddress = report.Address.String()
	}

	hostname := report.Hostname
	if hostname == "" {
		hostname = "-"
	}

	asnISP := "-"
	if report.ASN != "-" || report.Organization != "-" {
		asnISP = strings.TrimSpace(fmt.Sprintf("AS%s %s", report.ASN, report.Organization))
		if asnISP == "AS- -" {
			asnISP = "-"
		}
	}

	return fmt.Sprintf("%d\t%s\t%s\t%s\t%s", report.Number, rttColumn, ipAddress, hostname, asnISP)
}
