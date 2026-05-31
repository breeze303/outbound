//go:build xhttp_interop && xhttp_realnode

package v2ray

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	_ "github.com/daeuniverse/outbound/protocol/vless"
)

// TestVLESSXHTTPRealNodeConnectivity is intentionally behind
// `-tags 'xhttp_interop,xhttp_realnode'` because it uses a real VLESS XHTTP
// node instead of the local Xray reference server. It is optional and only
// runs when DAE_XHTTP_REAL_NODE_LINK is provided; any VM access details are
// expected to come from explicit environment overrides and are never embedded
// in source.
func TestVLESSXHTTPRealNodeConnectivity(t *testing.T) {
	link := os.Getenv("DAE_XHTTP_REAL_NODE_LINK")
	if strings.TrimSpace(link) == "" {
		t.Skip("DAE_XHTTP_REAL_NODE_LINK is unset; skipping optional real-node QA")
	}
	testURL := os.Getenv("DAE_XHTTP_REAL_TEST_URL")
	if testURL == "" {
		testURL = "https://www.gstatic.com/generate_204"
	}
	t.Logf("real-node QA target URL: %s", testURL)
	t.Logf("optional VM override envs: %s, %s, %s", "DAE_XHTTP_TEST_VM_HOST", "DAE_XHTTP_TEST_VM_USER", "DAE_XHTTP_TEST_VM_PASSWORD")
	t.Logf("using VLESS XHTTP link: %s", redactXHTTPInteropLink(link))

	d, _, err := NewV2Ray(&dialer.ExtraOption{}, xhttpInteropDirectDialer{}, link)
	if err != nil {
		t.Fatalf("NewV2Ray(real node) error = %v", err)
	}

	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := d.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return xhttpAsNetConn(conn), nil
		},
		TLSHandshakeTimeout: 10 * time.Second,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second}
	resp, err := client.Get(testURL)
	if err != nil {
		t.Fatalf("real-node HTTP GET failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		t.Fatalf("real-node HTTP status = %d, want 204 or 200", resp.StatusCode)
	}
	t.Logf("real-node VLESS XHTTP connectivity succeeded with status %d", resp.StatusCode)
}
func redactXHTTPInteropLink(link string) string {
	u, err := url.Parse(link)
	if err != nil {
		return "<invalid link>"
	}
	if u.User != nil {
		u.User = url.User("<redacted-uuid>")
	}
	q := u.Query()
	for _, key := range []string{"pbk", "sid", "pqv"} {
		if q.Get(key) != "" {
			q.Set(key, "<redacted>")
		}
	}
	u.RawQuery = q.Encode()
	return fmt.Sprintf("%s", u.String())
}

var _ netproxy.Dialer = xhttpInteropDirectDialer{}
