package naive

import (
	"errors"
	"strings"
	"testing"

	"github.com/daeuniverse/outbound/dialer"
)

func TestNewNaiveFailsExplicitly(t *testing.T) {
	_, _, err := dialer.NewNetproxyDialerFromLink(nil, nil, "naive://example.com:443")
	if err == nil {
		t.Fatal("expected unsupported error")
	}
	if !errors.Is(err, dialer.UnexpectedFieldErr) {
		t.Fatalf("expected UnexpectedFieldErr, got %v", err)
	}
	if !strings.Contains(err.Error(), "naive is unsupported") {
		t.Fatalf("expected naive unsupported message, got %v", err)
	}
}
