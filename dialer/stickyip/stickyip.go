package stickyip

import (
	"net"
	"sync"

	"github.com/daeuniverse/outbound/netproxy"
)

type ProxyIpCache struct {
	mu      sync.Mutex
	entries map[string]string
}

func NewProxyIpCache() *ProxyIpCache { return &ProxyIpCache{entries: make(map[string]string)} }

func (c *ProxyIpCache) Set(proxyAddr, cachedAddr, l4Proto, ipVersion string, _ int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = make(map[string]string)
	}
	c.entries[proxyAddr+"|"+l4Proto+"|"+ipVersion] = cachedAddr
}

func (c *ProxyIpCache) Invalidate(proxyAddr string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k := range c.entries {
		if len(k) >= len(proxyAddr) && k[:len(proxyAddr)] == proxyAddr {
			delete(c.entries, k)
		}
	}
}

func (c *ProxyIpCache) get(proxyAddr, l4Proto, ipVersion string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.entries[proxyAddr+"|"+l4Proto+"|"+ipVersion]
}

type StickyIpDialer struct {
	netproxy.Dialer
	proxyAddr string
	cache     *ProxyIpCache
	cycle     int
}

func NewStickyIpDialer(d netproxy.Dialer, proxyAddr string, cache *ProxyIpCache) *StickyIpDialer {
	if cache == nil {
		cache = NewProxyIpCache()
	}
	return &StickyIpDialer{Dialer: d, proxyAddr: proxyAddr, cache: cache}
}

func SplitHostPort(addr string) (host, port string, err error) { return net.SplitHostPort(addr) }
func (d *StickyIpDialer) IncrementCheckCycle()                 { d.cycle++ }
func (d *StickyIpDialer) GetCachedProxyAddrWithIpVersion(l4Proto, ipVersion string) string {
	return d.cache.get(d.proxyAddr, l4Proto, ipVersion)
}
func (d *StickyIpDialer) InvalidateProtocolAndIpVersionCache(proxyAddr, l4Proto, ipVersion string) {
	d.cache.Invalidate(proxyAddr)
}
func (d *StickyIpDialer) InvalidateProtocolCache(proxyAddr, l4Proto string) {
	d.cache.Invalidate(proxyAddr)
}
