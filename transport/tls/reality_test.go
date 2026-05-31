package tls

import (
	"crypto/ecdh"
	"crypto/rand"
	"strings"
	"testing"

	utls "github.com/refraction-networking/utls"
)

func TestRealityTLS13PrivateKeyPrefersEcdhe(t *testing.T) {
	ecdhe, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(Ecdhe): %v", err)
	}
	mlkemEcdhe, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(MlkemEcdhe): %v", err)
	}

	state := &utls.TLS13OnlyState{
		KeyShareKeys: &utls.KeySharePrivateKeys{
			Ecdhe:      ecdhe,
			MlkemEcdhe: mlkemEcdhe,
		},
	}

	if got := realityTLS13PrivateKey(state); got != ecdhe {
		t.Fatalf("realityTLS13PrivateKey() = %p, want Ecdhe %p", got, ecdhe)
	}
}

func TestRealityTLS13PrivateKeyFallsBackToMlkemEcdhe(t *testing.T) {
	mlkemEcdhe, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(MlkemEcdhe): %v", err)
	}

	state := &utls.TLS13OnlyState{
		KeyShareKeys: &utls.KeySharePrivateKeys{
			MlkemEcdhe: mlkemEcdhe,
		},
	}

	if got := realityTLS13PrivateKey(state); got != mlkemEcdhe {
		t.Fatalf("realityTLS13PrivateKey() = %p, want MlkemEcdhe %p", got, mlkemEcdhe)
	}
}

func TestRealityTLS13PrivateKeyNoKeyShare(t *testing.T) {
	legacyOnly, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(EcdheKey): %v", err)
	}

	state := &utls.TLS13OnlyState{
		EcdheKey: legacyOnly,
	}

	if got := realityTLS13PrivateKey(state); got != nil {
		t.Fatalf("realityTLS13PrivateKey() = %p, want nil when KeyShareKeys is missing", got)
	}

	err = realityNoTLS13KeyShareError(utls.HelloChrome_Auto)
	if err == nil {
		t.Fatal("realityNoTLS13KeyShareError() returned nil")
	}
	got := err.Error()
	if !strings.Contains(got, "does not support TLS 1.3 keyshare") {
		t.Fatalf("realityNoTLS13KeyShareError() = %q, want TLS 1.3 keyshare support message", got)
	}
	if !strings.Contains(got, "REALITY handshake cannot establish") {
		t.Fatalf("realityNoTLS13KeyShareError() = %q, want REALITY handshake failure message", got)
	}
}
