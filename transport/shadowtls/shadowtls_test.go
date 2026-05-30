package shadowtls

import (
	"errors"
	"strings"
	"testing"

	"github.com/daeuniverse/outbound/dialer"
)

func TestNewShadowTLSFailsExplicitly(t *testing.T) {
	_, _, err := dialer.NewNetproxyDialerFromLink(nil, nil, "shadowtls://example.com:443")
	if err == nil {
		t.Fatal("expected unsupported error")
	}
	if !errors.Is(err, dialer.UnexpectedFieldErr) {
		t.Fatalf("expected UnexpectedFieldErr, got %v", err)
	}
	if !strings.Contains(err.Error(), "shadowtls is unsupported") {
		t.Fatalf("expected shadowtls unsupported message, got %v", err)
	}
}
