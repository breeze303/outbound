package shadowsocks_2022

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
)

type failDialer struct{}

func (failDialer) DialContext(context.Context, string, string) (netproxy.Conn, error) {
	panic("SS2022 unsupported constructor must not return a dialer")
}

func testPSK(length int) string {
	return base64.StdEncoding.EncodeToString(make([]byte, length))
}

func TestNewDialerFailsClosedAfterValidatingPSK(t *testing.T) {
	_, err := NewDialer(failDialer{}, protocol.Header{
		Cipher:   "2022-blake3-aes-256-gcm",
		Password: testPSK(32),
	})
	if err == nil {
		t.Fatal("expected unsupported error")
	}
	if !strings.Contains(err.Error(), "shadowsocks 2022 is unsupported") {
		t.Fatalf("expected unsupported error, got %v", err)
	}
}

func TestNewDialerStillRejectsInvalidPSKBeforeUnsupported(t *testing.T) {
	_, err := NewDialer(failDialer{}, protocol.Header{
		Cipher:   "2022-blake3-aes-256-gcm",
		Password: testPSK(31),
	})
	if err == nil {
		t.Fatal("expected PSK length error")
	}
	if !strings.Contains(err.Error(), "PSK length must be 32 bytes") {
		t.Fatalf("expected PSK length error, got %v", err)
	}
}
