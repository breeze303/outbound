package naive

import (
	"fmt"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
)

func init() {
	dialer.FromLinkRegister("naive", NewNaive)
	dialer.FromLinkRegister("naive+https", NewNaive)
	dialer.FromLinkRegister("naive+quic", NewNaive)
}

func NewNaive(_ *dialer.ExtraOption, _ netproxy.Dialer, _ string) (netproxy.Dialer, *dialer.Property, error) {
	return nil, nil, fmt.Errorf("%w: naive is unsupported in this outbound compatibility build", dialer.UnexpectedFieldErr)
}
