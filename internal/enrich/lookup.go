package enrich

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

const lookupTimeout = 2 * time.Second

// HostInfo holds reverse DNS and ASN metadata for a hop address.
type HostInfo struct {
	Hostname string
	ASN      string
	Organization string
}

// LookupHostMetadata performs PTR and Team Cymru ASN TXT enrichment with timeouts.
func LookupHostMetadata(parent context.Context, ipAddress net.IP) HostInfo {
	if ipAddress == nil {
		return HostInfo{Hostname: "-", ASN: "-", Organization: "-"}
	}

	lookupContext, cancel := context.WithTimeout(parent, lookupTimeout)
	defer cancel()

	hostname := reversePTR(lookupContext, ipAddress)
	asnNumber, organization := cymruASN(lookupContext, ipAddress)
	return HostInfo{
		Hostname:     hostname,
		ASN:          asnNumber,
		Organization: organization,
	}
}

func reversePTR(ctx context.Context, ipAddress net.IP) string {
	names, err := net.DefaultResolver.LookupAddr(ctx, ipAddress.String())
	if err != nil || len(names) == 0 {
		return "-"
	}
	return strings.TrimSuffix(names[0], ".")
}

func cymruASN(ctx context.Context, ipAddress net.IP) (string, string) {
	ipv4 := ipAddress.To4()
	if ipv4 == nil {
		return "-", "-"
	}
	queryName := fmt.Sprintf("%s.origin.asn.cymru.com", reverseOctets(ipv4))
	textRecords, err := net.DefaultResolver.LookupTXT(ctx, queryName)
	if err != nil || len(textRecords) == 0 {
		return "-", "-"
	}
	fields := strings.Split(textRecords[0], " | ")
	if len(fields) < 1 {
		return "-", "-"
	}
	asnNumber := strings.TrimSpace(fields[0])
	organization := "-"
	if len(fields) >= 6 {
		organization = strings.TrimSpace(fields[5])
	}
	return asnNumber, organization
}

func reverseOctets(ipv4 net.IP) string {
	octets := strings.Split(ipv4.String(), ".")
	for left, right := 0, len(octets)-1; left < right; left, right = left+1, right-1 {
		octets[left], octets[right] = octets[right], octets[left]
	}
	return strings.Join(octets, ".")
}
