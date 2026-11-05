package trace

import (
	"context"
	"strings"
	"testing"
)

func TestHopLineParsing(t *testing.T) {
	sample := `
 1?: [LOCALHOST]                      pmtu 1500
 1:  10.0.0.1                                           0.123ms 
 2:  no reply
`
	var count int
	for _, line := range strings.Split(sample, "\n") {
		if hopLine.FindStringSubmatch(line) != nil {
			count++
		}
	}
	if count != 2 {
		t.Fatalf("expected 2 parsed hop lines, got %d", count)
	}
}

func TestRunValidation(t *testing.T) {
	t.Parallel()
	if _, err := Run(context.Background(), "", 5); err == nil {
		t.Fatal("expected error for empty host")
	}
	if _, err := Run(context.Background(), "example.com", 0); err == nil {
		t.Fatal("expected error for maxHops 0")
	}
}
