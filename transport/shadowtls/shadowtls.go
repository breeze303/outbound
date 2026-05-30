package shadowtls

import (
	"fmt"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
)

func init() {
	dialer.FromLinkRegister("shadowtls", NewShadowTLS)
	dialer.FromLinkRegister("shadow-tls", NewShadowTLS)
	dialer.FromLinkRegister("sstls", NewShadowTLS)
}

func NewShadowTLS(_ *dialer.ExtraOption, _ netproxy.Dialer, _ string) (netproxy.Dialer, *dialer.Property, error) {
	return nil, nil, fmt.Errorf("%w: shadowtls is unsupported in this outbound compatibility build", dialer.UnexpectedFieldErr)
}
