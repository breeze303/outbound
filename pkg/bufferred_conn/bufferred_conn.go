package bufferred_conn

import (
	"net"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pkg/zeroalloc/bufio"
)

type BufferedConn struct {
	r        *bufio.Reader
	net.Conn // So that most methods are embedded
}

var _ interface {
	netproxy.UnderlyingConnProvider
	relayPrefixSource
	ReadByte() (byte, error)
	UnreadByte() error
} = (*BufferedConn)(nil)

type relayPrefixSource interface {
	TakeRelayPrefix() []byte
	TakeRelaySegments() [][]byte
}

func NewBufferedConn(c net.Conn) *BufferedConn {
	return &BufferedConn{bufio.NewReader(c), c}
}

func NewBufferedConnSize(c net.Conn, n int) *BufferedConn {
	return &BufferedConn{bufio.NewReaderSize(c, n), c}
}

func (b BufferedConn) Peek(n int) ([]byte, error) {
	return b.r.Peek(n)
}

func (b BufferedConn) Close() error {
	b.r.Put()
	return b.Conn.Close()
}

func (b BufferedConn) Read(p []byte) (int, error) {
	return b.r.Read(p)
}

func (b *BufferedConn) UnderlyingConn() net.Conn {
	if b == nil {
		return nil
	}
	return b.Conn
}

func (b *BufferedConn) TakeRelayPrefix() []byte {
	if b == nil || b.r == nil {
		return nil
	}
	if n := b.r.Buffered(); n > 0 {
		prefix, _ := b.r.Peek(n)
		if len(prefix) > 0 {
			_, _ = b.r.Discard(len(prefix))
			return prefix
		}
	}
	return nil
}

func (b *BufferedConn) TakeRelaySegments() [][]byte {
	prefix := b.TakeRelayPrefix()
	if len(prefix) == 0 {
		return nil
	}
	return [][]byte{prefix}
}

func (c *BufferedConn) ReadByte() (byte, error) {
	return c.r.ReadByte()
}

func (c *BufferedConn) UnreadByte() error {
	return c.r.UnreadByte()
}
