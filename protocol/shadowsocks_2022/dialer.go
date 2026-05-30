package shadowsocks_2022

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
)

func init() { protocol.Register("shadowsocks_2022", NewDialer) }

func NewDialer(nextDialer netproxy.Dialer, header protocol.Header) (netproxy.Dialer, error) {
	if !strings.HasPrefix(header.Cipher, "2022-blake3-") {
		return nil, fmt.Errorf("unsupported shadowsocks encryption method: %v", header.Cipher)
	}
	if len(header.Password) == 0 {
		return nil, fmt.Errorf("PSK cannot be empty")
	}
	psks := strings.Split(header.Password, ":")
	switch header.Cipher {
	case "2022-blake3-aes-128-gcm":
		for _, psk := range psks {
			decoded, err := base64.StdEncoding.DecodeString(psk)
			if err != nil {
				return nil, fmt.Errorf("PSK must be valid base64")
			}
			if len(decoded) != 16 {
				return nil, fmt.Errorf("PSK length must be 16 bytes")
			}
		}
	case "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305":
		for _, psk := range psks {
			decoded, err := base64.StdEncoding.DecodeString(psk)
			if err != nil {
				return nil, fmt.Errorf("PSK must be valid base64")
			}
			if len(decoded) != 32 {
				return nil, fmt.Errorf("PSK length must be 32 bytes")
			}
		}
	default:
		return nil, fmt.Errorf("unsupported shadowsocks encryption method: %v", header.Cipher)
	}
	return nil, fmt.Errorf("shadowsocks 2022 is unsupported: encryption/framing is not implemented")
}
