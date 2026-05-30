//go:build xhttp_interop

package v2ray

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	_ "github.com/daeuniverse/outbound/protocol/vless"
)

const xhttpInteropUserID = "00000000-0000-0000-0000-000000000000"

var (
	xrayInteropBinaryOnce sync.Once
	xrayInteropBinaryPath string
	xrayInteropBinaryErr  error
	xrayInteropBuildLog   bytes.Buffer
)

func TestVLESSXHTTPInterop(t *testing.T) {
	tests := []struct {
		name          string
		security      string
		alpn          string
		mode          string
		wantResolved  string
		extra         string
		serverXHTTP   map[string]any
		targetPath    string
		targetBody    string
		minWriteBytes int
	}{
		{
			name:         "h1_no_tls_packet_up_with_extra",
			mode:         XHTTPModePacketUp,
			wantResolved: XHTTPModePacketUp,
			extra:        `{"scMaxEachPostBytes":64,"xPaddingBytes":100}`,
			serverXHTTP: map[string]any{
				"mode": "packet-up",
			},
			targetPath:    "/h1-packet-up",
			targetBody:    "xray-h1-packet-up-ok",
			minWriteBytes: 192,
		},
		{
			name:         "h2_tls_auto_stream_up_default_padding",
			security:     "tls",
			alpn:         "h2,http/1.1",
			mode:         XHTTPModeAuto,
			wantResolved: XHTTPModeStreamUp,
			serverXHTTP: map[string]any{
				"mode": "auto",
			},
			targetPath: "/h2-stream-up",
			targetBody: "xray-h2-stream-up-ok",
		},
	}

	bin := xrayInteropBinary(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := newXHTTPInteropTarget(t, tt.targetPath, tt.targetBody)
			defer target.Close()

			listenHost, listenPort := xhttpInteropFreeTCPAddr(t)
			configPath := xhttpInteropConfig(t, xhttpInteropServerConfig{
				ListenHost: listenHost,
				ListenPort: listenPort,
				Security:   tt.security,
				ALPN:       tt.alpn,
				XHTTP:      tt.serverXHTTP,
			})
			cmd := startXrayInteropServer(t, bin, configPath, net.JoinHostPort(listenHost, listenPort))
			defer cmd.stop()

			link := xhttpInteropLink(t, listenHost, listenPort, tt.security, tt.alpn, tt.mode, tt.extra)
			parsed, err := ParseVlessURL(link)
			if err != nil {
				t.Fatalf("ParseVlessURL() error = %v", err)
			}
			if parsed.XHTTP == nil || parsed.XHTTP.ResolvedMode != tt.wantResolved {
				t.Fatalf("resolved mode = %#v, want %q", parsed.XHTTP, tt.wantResolved)
			}

			d, _, err := NewV2Ray(&dialer.ExtraOption{AllowInsecure: true}, xhttpInteropDirectDialer{}, link)
			if err != nil {
				t.Fatalf("NewV2Ray() error = %v", err)
			}
			status, body := xhttpInteropHTTPRequest(t, d, target.Addr(), tt.targetPath, tt.minWriteBytes)
			if status != http.StatusOK || body != tt.targetBody {
				t.Fatalf("HTTP response = %d %q, want 200 %q", status, body, tt.targetBody)
			}
			if got := target.RequestCount(); got != 1 {
				t.Fatalf("target request count = %d, want 1", got)
			}
			t.Logf("interop %s succeeded through Xray %s to target %s", tt.name, net.JoinHostPort(listenHost, listenPort), target.Addr())
		})
	}
}

func TestVLESSXHTTPInteropInvalid(t *testing.T) {
	tests := []struct {
		name      string
		query     url.Values
		wantErr   error
		wantField string
	}{
		{
			name: "invalid mode",
			query: url.Values{
				"type": {"xhttp"},
				"mode": {"stream-two"},
			},
			wantErr:   dialer.InvalidParameterErr,
			wantField: "xhttp mode",
		},
		{
			name: "headers host",
			query: url.Values{
				"type":         {"xhttp"},
				"headers.host": {"forbidden.example"},
			},
			wantErr:   dialer.UnexpectedFieldErr,
			wantField: "headers.host",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertXHTTPRejectsBeforeDial(t, tt.query, tt.wantErr, tt.wantField)
		})
	}
}

type xhttpInteropServerConfig struct {
	ListenHost string
	ListenPort string
	Security   string
	ALPN       string
	XHTTP      map[string]any
}

func xrayInteropBinary(t *testing.T) string {
	t.Helper()
	xrayInteropBinaryOnce.Do(func() {
		if bin := os.Getenv("XRAY_BIN"); bin != "" {
			xrayInteropBinaryPath = bin
			return
		}
		workspace, err := xhttpInteropWorkspaceRoot()
		if err != nil {
			xrayInteropBinaryErr = err
			return
		}
		xrayRoot := filepath.Join(workspace, "Xray-core")
		tmp, err := os.MkdirTemp("", "dae-xhttp-xray-bin-*")
		if err != nil {
			xrayInteropBinaryErr = err
			return
		}
		xrayInteropBinaryPath = filepath.Join(tmp, "xray")
		cmd := exec.Command("go", "build", "-o", xrayInteropBinaryPath, "./main")
		cmd.Dir = xrayRoot
		cmd.Stdout = &xrayInteropBuildLog
		cmd.Stderr = &xrayInteropBuildLog
		xrayInteropBinaryErr = cmd.Run()
	})
	if xrayInteropBinaryErr != nil {
		t.Fatalf("resolve/build Xray binary failed: %v\n%s", xrayInteropBinaryErr, xrayInteropBuildLog.String())
	}
	return xrayInteropBinaryPath
}

func xhttpInteropWorkspaceRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		modPath := filepath.Join(dir, "go.mod")
		if b, err := os.ReadFile(modPath); err == nil && strings.Contains(string(b), "module github.com/daeuniverse/outbound") {
			return filepath.Dir(dir), nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("failed to locate outbound module root from %s", dir)
		}
		dir = parent
	}
}

func xhttpInteropConfig(t *testing.T, cfg xhttpInteropServerConfig) string {
	t.Helper()
	xhttpSettings := map[string]any{
		"host": "localhost",
		"path": "/xhttp-interop",
	}
	for k, v := range cfg.XHTTP {
		xhttpSettings[k] = v
	}

	streamSettings := map[string]any{
		"network":       "xhttp",
		"xhttpSettings": xhttpSettings,
	}
	if cfg.Security == "tls" {
		certFile, keyFile := xhttpInteropCertificate(t)
		streamSettings["security"] = "tls"
		streamSettings["tlsSettings"] = map[string]any{
			"alpn": splitXHTTPALPN(cfg.ALPN),
			"certificates": []map[string]any{{
				"certificateFile": certFile,
				"keyFile":         keyFile,
			}},
		}
	}

	xrayConfig := map[string]any{
		"log": map[string]any{
			"loglevel": "debug",
		},
		"inbounds": []map[string]any{{
			"listen":   cfg.ListenHost,
			"port":     xhttpInteropAtoi(t, cfg.ListenPort),
			"protocol": "vless",
			"settings": map[string]any{
				"decryption": "none",
				"clients": []map[string]any{{
					"id": xhttpInteropUserID,
				}},
			},
			"streamSettings": streamSettings,
		}},
		"outbounds": []map[string]any{{
			"protocol": "freedom",
			"settings": map[string]any{
				"finalRules": []map[string]any{{
					"action": "allow",
				}},
			},
		}},
	}

	path := filepath.Join(t.TempDir(), "xray-server.json")
	b, err := json.MarshalIndent(xrayConfig, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote Xray interop config %s", path)
	return path
}

func xhttpInteropCertificate(t *testing.T) (string, string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	certOut := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyOut := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	if err := os.WriteFile(certFile, certOut, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyOut, 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

type xrayInteropCommand struct {
	cmd    *exec.Cmd
	stdout bytes.Buffer
	stderr bytes.Buffer
}

func startXrayInteropServer(t *testing.T, bin, configPath, addr string) *xrayInteropCommand {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	run := &xrayInteropCommand{cmd: exec.CommandContext(ctx, bin, "run", "-config", configPath)}
	run.cmd.Stdout = &run.stdout
	run.cmd.Stderr = &run.stderr
	if err := run.cmd.Start(); err != nil {
		t.Fatalf("start Xray failed: %v", err)
	}
	if err := waitXHTTPInteropTCP(addr, 10*time.Second); err != nil {
		run.stop()
		t.Fatalf("Xray did not start on %s: %v\nstdout:\n%s\nstderr:\n%s", addr, err, run.stdout.String(), run.stderr.String())
	}
	t.Logf("started Xray pid=%d addr=%s", run.cmd.Process.Pid, addr)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("Xray stdout:\n%s", run.stdout.String())
			t.Logf("Xray stderr:\n%s", run.stderr.String())
		}
	})
	return run
}

func (c *xrayInteropCommand) stop() {
	if c == nil || c.cmd == nil || c.cmd.Process == nil {
		return
	}
	_ = c.cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		_, _ = c.cmd.Process.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		_ = c.cmd.Process.Kill()
		<-done
	}
}

func waitXHTTPInteropTCP(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		lastErr = err
		time.Sleep(100 * time.Millisecond)
	}
	return lastErr
}

func xhttpInteropLink(t *testing.T, host, port, security, alpn, mode, extra string) string {
	t.Helper()
	q := url.Values{
		"type": {"xhttp"},
		"path": {"/xhttp-interop"},
		"host": {"localhost"},
	}
	if security == "" {
		security = "none"
	}
	q.Set("security", security)
	if security == "tls" {
		q.Set("sni", "localhost")
	}
	if alpn != "" {
		q.Set("alpn", alpn)
	}
	if mode != "" {
		q.Set("mode", mode)
	}
	if extra != "" {
		q.Set("extra", extra)
	}
	return (&url.URL{
		Scheme:   "vless",
		User:     url.User(xhttpInteropUserID),
		Host:     net.JoinHostPort(host, port),
		RawQuery: q.Encode(),
		Fragment: "xhttp-interop",
	}).String()
}

type xhttpInteropDirectDialer struct{}

func (xhttpInteropDirectDialer) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	var d net.Dialer
	return d.DialContext(ctx, magicNetwork.Network, addr)
}

func xhttpInteropHTTPRequest(t *testing.T, d netproxy.Dialer, targetAddr, path string, minWriteBytes int) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		t.Fatalf("DialContext(%s) error = %v", targetAddr, err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatalf("SetDeadline() error = %v", err)
	}
	body := ""
	if minWriteBytes > 0 {
		body = strings.Repeat("a", minWriteBytes)
	}
	method := http.MethodGet
	if body != "" {
		method = http.MethodPost
	}
	req := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nContent-Length: %d\r\n\r\n%s", method, path, targetAddr, len(body), body)
	if _, err := io.WriteString(conn, req); err != nil {
		t.Fatalf("write HTTP request error = %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read HTTP response error = %v", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body error = %v", err)
	}
	return resp.StatusCode, string(respBody)
}

type xhttpInteropTarget struct {
	server *http.Server
	ln     net.Listener
	mu     sync.Mutex
	count  int
}

func newXHTTPInteropTarget(t *testing.T, path, body string) *xhttpInteropTarget {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	target := &xhttpInteropTarget{ln: ln}
	target.server = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, _ = io.Copy(io.Discard, req.Body)
		_ = req.Body.Close()
		target.mu.Lock()
		target.count++
		target.mu.Unlock()
		if req.URL.Path != path {
			http.Error(w, "unexpected path", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	})}
	go func() {
		_ = target.server.Serve(ln)
	}()
	return target
}

func (t *xhttpInteropTarget) Addr() string {
	return t.ln.Addr().String()
}

func (t *xhttpInteropTarget) RequestCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.count
}

func (t *xhttpInteropTarget) Close() {
	_ = t.server.Close()
}

func xhttpInteropFreeTCPAddr(t *testing.T) (string, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	host, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return host, port
}

func xhttpInteropAtoi(t *testing.T, s string) int {
	t.Helper()
	var v int
	if _, err := fmt.Sscanf(s, "%d", &v); err != nil {
		t.Fatal(err)
	}
	return v
}
