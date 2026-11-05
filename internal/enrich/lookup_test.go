package enrich

import (
	"net"
	"testing"
)

func TestReverseOctets(t *testing.T) {
	got := reverseOctets(net.IPv4(8, 8, 4, 4))
	if got != "4.4.8.8" {
		t.Fatalf("got %q", got)
	}
}
