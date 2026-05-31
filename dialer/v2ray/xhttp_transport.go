package v2ray

import (
	"bytes"
	"context"
	"crypto/rand"
	gotls "crypto/tls"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	transporttls "github.com/daeuniverse/outbound/transport/tls"
	"github.com/google/uuid"
	"golang.org/x/net/http2"
)

const (
	xhttpHTTPVersion1 = "1.1"
	xhttpHTTPVersion2 = "2"

	xhttpDefaultXPaddingBytesFrom = 100
	xhttpDefaultXPaddingBytesTo   = 1000

	xhttpCloseUploadGrace = 200 * time.Millisecond
	xhttpCloseCancelGrace = 200 * time.Millisecond
)

type xhttpDialer struct {
	nextDialer    netproxy.Dialer
	realityDialer netproxy.Dialer
	addr          string
	scheme        string
	host          string
	serverName    string
	security      string
	alpn          []string
	allowInsecure bool
	httpVersion   string
	config        *XHTTPConfig
	tlsConfig     *gotls.Config
}

func newXHTTPDialer(option *dialer.ExtraOption, nextDialer netproxy.Dialer, s *V2Ray) (netproxy.Dialer, error) {
	if s.Protocol != "vless" {
		return nil, fmt.Errorf("%w: network: %v", dialer.UnexpectedFieldErr, s.Net)
	}
	if s.XHTTP == nil {
		return nil, fmt.Errorf("%w: xhttp config is missing", dialer.InvalidParameterErr)
	}
	if option == nil {
		option = &dialer.ExtraOption{}
	}

	security := strings.ToLower(s.TLS)
	scheme := "http"
	if security == "tls" || security == "reality" {
		scheme = "https"
	}

	serverName := s.SNI
	if serverName == "" {
		serverName = s.Host
	}
	if serverName == "" {
		serverName = s.Add
	}

	alpn := splitXHTTPALPN(s.Alpn)
	if (security == "tls" || security == "reality") && len(alpn) == 0 {
		alpn = []string{"h2", "http/1.1"}
	}

	x := &xhttpDialer{
		nextDialer:    nextDialer,
		addr:          net.JoinHostPort(s.Add, s.Port),
		scheme:        scheme,
		host:          s.XHTTP.Host,
		serverName:    serverName,
		security:      security,
		alpn:          alpn,
		allowInsecure: s.AllowInsecure || option.AllowInsecure,
		httpVersion:   decideXHTTPHTTPVersion(security, s.Alpn),
		config:        s.XHTTP,
	}
	if x.host == "" {
		x.host = s.Add
	}

	if security == "tls" {
		x.tlsConfig = &gotls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: x.allowInsecure,
			NextProtos:         alpn,
		}
	}
	if security == "reality" {
		realityURL := url.URL{
			Scheme: "reality",
			Host:   x.addr,
			RawQuery: url.Values{
				"sni": []string{serverName},
				"fp":  []string{s.Fingerprint},
				"sid": []string{s.ShortId},
				"pbk": []string{s.PublicKey},
				"spx": []string{s.SpiderX},
				"pqv": []string{s.Mldsa65Verify},
			}.Encode(),
		}
		realityDialer, err := transporttls.NewReality(realityURL.String(), nextDialer)
		if err != nil {
			return nil, err
		}
		x.realityDialer = realityDialer
	}

	return x, nil
}

func decideXHTTPHTTPVersion(security, alpn string) string {
	switch strings.ToLower(security) {
	case "reality":
		return xhttpHTTPVersion2
	case "tls":
		protocols := splitXHTTPALPN(alpn)
		if len(protocols) == 1 && protocols[0] == "http/1.1" {
			return xhttpHTTPVersion1
		}
		return xhttpHTTPVersion2
	default:
		return xhttpHTTPVersion1
	}
}

func (d *xhttpDialer) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	if magicNetwork.Network != "tcp" {
		return nil, fmt.Errorf("%w: xhttp+%v", netproxy.UnsupportedTunnelTypeError, magicNetwork.Network)
	}

	connCtx, cancel := context.WithCancel(context.Background())
	setupCtx, setupCancel := context.WithCancel(connCtx)
	stopSetupCancel := context.AfterFunc(ctx, setupCancel)
	client, closeIdle := d.newHTTPClient(network)
	sessionID := ""
	if d.config.ResolvedMode != XHTTPModeStreamOne {
		sessionID = uuid.NewString()
	}

	c := &xhttpConn{
		dialer:    d,
		client:    client,
		closeIdle: closeIdle,
		ctx:       connCtx,
		cancel:    cancel,
		mode:      d.config.ResolvedMode,
		sessionID: sessionID,
		closed:    make(chan struct{}),
	}

	switch d.config.ResolvedMode {
	case XHTTPModePacketUp:
		c.reader = d.openDownstream(setupCtx, client, d.urlWithSession(sessionID))
	case XHTTPModeStreamUp:
		c.reader = d.openDownstream(setupCtx, client, d.urlWithSession(sessionID))
		pr, pw := io.Pipe()
		c.uploadWriter = pw
		c.uploadDone = make(chan struct{})
		go c.doStreamUpload(pr, d.urlWithSession(sessionID))
	case XHTTPModeStreamOne:
		pr, pw := io.Pipe()
		c.uploadWriter = pw
		c.uploadDone = make(chan struct{})
		c.reader = d.openStreamOne(setupCtx, client, d.baseURL(), pr, c.uploadDone)
	default:
		stopSetupCancel()
		setupCancel()
		cancel()
		return nil, fmt.Errorf("%w: xhttp mode: %v", dialer.InvalidParameterErr, d.config.ResolvedMode)
	}
	if c.mode != XHTTPModeStreamOne {
		if err := c.reader.waitReady(ctx); err != nil {
			stopSetupCancel()
			setupCancel()
			_ = c.Close()
			return nil, err
		}
	}
	if !stopSetupCancel() {
		select {
		case <-ctx.Done():
			setupCancel()
			_ = c.Close()
			return nil, ctx.Err()
		default:
		}
	}

	return c, nil
}

func (d *xhttpDialer) newHTTPClient(network string) (*http.Client, func()) {
	if d.httpVersion == xhttpHTTPVersion2 {
		transport := &http2.Transport{
			DialTLSContext: func(ctx context.Context, _, _ string, _ *gotls.Config) (net.Conn, error) {
				return d.dialTLS(ctx, network)
			},
		}
		return &http.Client{Transport: transport}, transport.CloseIdleConnections
	}

	transport := &http.Transport{
		DisableCompression: true,
		DisableKeepAlives:  true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return d.dialPlain(ctx, network)
		},
		DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return d.dialTLS(ctx, network)
		},
		ForceAttemptHTTP2: false,
	}
	return &http.Client{Transport: transport}, transport.CloseIdleConnections
}

func (d *xhttpDialer) dialPlain(ctx context.Context, network string) (net.Conn, error) {
	rawConn, err := d.nextDialer.DialContext(ctx, network, d.addr)
	if err != nil {
		return nil, err
	}
	return xhttpAsNetConn(rawConn), nil
}

func (d *xhttpDialer) dialTLS(ctx context.Context, network string) (net.Conn, error) {
	if d.security == "reality" {
		rawConn, err := d.realityDialer.DialContext(ctx, network, d.addr)
		if err != nil {
			return nil, err
		}
		return xhttpAsNetConn(rawConn), nil
	}

	rawConn, err := d.nextDialer.DialContext(ctx, network, d.addr)
	if err != nil {
		return nil, err
	}
	netConn := xhttpAsNetConn(rawConn)
	tlsConn := gotls.Client(netConn, d.tlsConfig.Clone())
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = netConn.Close()
		return nil, err
	}
	return tlsConn, nil
}

func xhttpAsNetConn(conn netproxy.Conn) net.Conn {
	if netConn, ok := conn.(net.Conn); ok {
		return netConn
	}
	return &netproxy.FakeNetConn{Conn: conn}
}

func (d *xhttpDialer) baseURL() url.URL {
	return url.URL{
		Scheme:   d.scheme,
		Host:     xhttpURLHost(d.host),
		Path:     d.config.Path,
		RawQuery: d.config.Query,
	}
}

func xhttpURLHost(host string) string {
	if strings.HasPrefix(host, "[") {
		return host
	}
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		return "[" + host + "]"
	}
	return host
}

func (d *xhttpDialer) urlWithSession(sessionID string) url.URL {
	u := d.baseURL()
	u.Path = appendXHTTPPath(u.Path, sessionID)
	return u
}

func (d *xhttpDialer) urlWithPacket(sessionID string, seq int64) url.URL {
	u := d.baseURL()
	u.Path = appendXHTTPPath(u.Path, sessionID, strconv.FormatInt(seq, 10))
	return u
}

func appendXHTTPPath(path string, values ...string) string {
	path = strings.TrimRight(path, "/")
	if path == "" {
		path = "/"
	}
	for _, value := range values {
		if value == "" {
			continue
		}
		if path == "/" {
			path += value
		} else {
			path += "/" + value
		}
	}
	return path
}

func (d *xhttpDialer) newRequest(ctx context.Context, method string, u url.URL, body io.Reader, grpcContentType bool) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, err
	}
	if grpcContentType {
		req.Header.Set("Content-Type", "application/grpc")
	}
	req.Header.Set("Referer", d.paddingReferer(&u))
	return req, nil
}

func (d *xhttpDialer) paddingReferer(u *url.URL) string {
	ref := *u
	ref.RawQuery = "x_padding=" + strings.Repeat("X", d.paddingLength())
	return ref.String()
}

func (d *xhttpDialer) paddingLength() int {
	r := d.config.XPaddingBytes
	if r.IsZero() {
		r = XHTTPRange{From: xhttpDefaultXPaddingBytesFrom, To: xhttpDefaultXPaddingBytesTo}
	}
	if r.From <= 0 {
		return xhttpDefaultXPaddingBytesFrom
	}
	if r.To <= r.From {
		return int(r.From)
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(r.To-r.From+1)))
	if err != nil {
		return int(r.From)
	}
	return int(r.From + int32(n.Int64()))
}

func (d *xhttpDialer) maxPacketUploadBytes() int {
	maxUpload := int(d.config.ScMaxEachPostBytes.To)
	if maxUpload <= 0 {
		maxUpload = xhttpDefaultScMaxEachPostBytes
	}
	return maxUpload
}

func (d *xhttpDialer) openDownstream(ctx context.Context, client *http.Client, u url.URL) *xhttpWaitReadCloser {
	reader := newXHTTPWaitReadCloser()
	go func() {
		req, err := d.newRequest(ctx, http.MethodGet, u, nil, false)
		if err != nil {
			reader.closeWithError(err)
			return
		}
		resp, err := client.Do(req)
		if err != nil {
			reader.closeWithError(err)
			return
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			reader.closeWithError(fmt.Errorf("xhttp GET %s: %s", u.String(), resp.Status))
			return
		}
		reader.set(resp.Body)
	}()
	return reader
}

func (d *xhttpDialer) openStreamOne(ctx context.Context, client *http.Client, u url.URL, body *io.PipeReader, uploadDone chan struct{}) *xhttpWaitReadCloser {
	reader := newXHTTPWaitReadCloser()
	go func() {
		if uploadDone != nil {
			defer close(uploadDone)
		}
		req, err := d.newRequest(ctx, http.MethodPost, u, body, true)
		if err != nil {
			_ = body.CloseWithError(err)
			reader.closeWithError(err)
			return
		}
		resp, err := client.Do(req)
		if err != nil {
			_ = body.CloseWithError(err)
			reader.closeWithError(err)
			return
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			err := fmt.Errorf("xhttp POST %s: %s", u.String(), resp.Status)
			_ = body.CloseWithError(err)
			reader.closeWithError(err)
			return
		}
		reader.set(resp.Body)
	}()
	return reader
}

type xhttpConn struct {
	dialer       *xhttpDialer
	client       *http.Client
	closeIdle    func()
	ctx          context.Context
	cancel       context.CancelFunc
	mode         string
	sessionID    string
	reader       *xhttpWaitReadCloser
	uploadWriter *io.PipeWriter
	uploadDone   chan struct{}
	seq          int64
	writeMu      sync.Mutex
	closeOnce    sync.Once
	closed       chan struct{}
	uploadErrMu  sync.Mutex
	uploadErr    error

	deadlineMu    sync.Mutex
	readDeadline  time.Time
	writeDeadline time.Time
	readTimer     *time.Timer
	writeTimer    *time.Timer
}

func (c *xhttpConn) Read(p []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}
	if err := c.checkReadDeadline(); err != nil {
		return 0, err
	}
	return c.reader.Read(p)
}

func (c *xhttpConn) Write(p []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}
	if err := c.getUploadError(); err != nil {
		return 0, err
	}
	if err := c.checkWriteDeadline(); err != nil {
		return 0, err
	}

	switch c.mode {
	case XHTTPModeStreamUp, XHTTPModeStreamOne:
		if c.uploadWriter == nil {
			return 0, io.ErrClosedPipe
		}
		n, err := c.uploadWriter.Write(p)
		if err != nil {
			return n, mapXHTTPDeadlineError(err)
		}
		if uploadErr := c.getUploadError(); uploadErr != nil {
			return n, uploadErr
		}
		return n, nil
	case XHTTPModePacketUp:
		return c.writePacketUp(p)
	default:
		return 0, fmt.Errorf("%w: xhttp mode: %v", dialer.InvalidParameterErr, c.mode)
	}
}

func (c *xhttpConn) writePacketUp(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if len(p) == 0 {
		return 0, nil
	}
	maxUpload := c.dialer.maxPacketUploadBytes()
	written := 0
	for written < len(p) {
		if err := c.checkWriteDeadline(); err != nil {
			return written, err
		}
		end := min(written+maxUpload, len(p))
		chunk := p[written:end]
		ctx, cancel, err := c.writeContext()
		if err != nil {
			return written, err
		}
		err = c.postPacket(ctx, chunk, c.seq)
		cancel()
		if err != nil {
			return written, mapXHTTPDeadlineError(err)
		}
		c.seq++
		written = end
	}
	return len(p), nil
}

func (c *xhttpConn) postPacket(ctx context.Context, payload []byte, seq int64) error {
	req, err := c.dialer.newRequest(ctx, http.MethodPost, c.dialer.urlWithPacket(c.sessionID, seq), bytes.NewReader(payload), false)
	if err != nil {
		return err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("xhttp packet POST: %s", resp.Status)
	}
	return nil
}

func (c *xhttpConn) doStreamUpload(body *io.PipeReader, u url.URL) {
	if c.uploadDone != nil {
		defer close(c.uploadDone)
	}
	req, err := c.dialer.newRequest(c.ctx, http.MethodPost, u, body, true)
	if err != nil {
		_ = body.CloseWithError(err)
		c.setUploadError(err)
		return
	}
	resp, err := c.client.Do(req)
	if err != nil {
		_ = body.CloseWithError(err)
		if !c.isClosed() {
			c.setUploadError(mapXHTTPDeadlineError(err))
		}
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("xhttp stream POST %s: %s", u.String(), resp.Status)
		_ = body.CloseWithError(err)
		c.setUploadError(err)
	}
}

func (c *xhttpConn) Close() error {
	var closeErr error
	c.closeOnce.Do(func() {
		close(c.closed)
		if c.uploadWriter != nil {
			_ = c.uploadWriter.Close()
			if !c.waitForUploadDone(xhttpCloseUploadGrace) {
				c.cancel()
				c.waitForUploadDone(xhttpCloseCancelGrace)
			} else {
				c.cancel()
			}
		} else {
			c.cancel()
		}
		if c.reader != nil {
			_ = c.reader.Close()
		}
		c.stopDeadlineTimers()
		if c.closeIdle != nil {
			c.closeIdle()
		}
		closeErr = c.getUploadError()
	})
	return closeErr
}

func (c *xhttpConn) isClosed() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}

func (c *xhttpConn) waitForUploadDone(timeout time.Duration) bool {
	if c.uploadDone == nil {
		return true
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-c.uploadDone:
		return true
	case <-timer.C:
		return false
	}
}

func (c *xhttpConn) setUploadError(err error) {
	if err == nil {
		return
	}
	c.uploadErrMu.Lock()
	if c.uploadErr == nil {
		c.uploadErr = err
	}
	c.uploadErrMu.Unlock()
	if c.reader != nil {
		c.reader.closeWithError(err)
	}
}

func (c *xhttpConn) getUploadError() error {
	c.uploadErrMu.Lock()
	defer c.uploadErrMu.Unlock()
	return c.uploadErr
}

func (c *xhttpConn) stopDeadlineTimers() {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	if c.readTimer != nil {
		c.readTimer.Stop()
		c.readTimer = nil
	}
	if c.writeTimer != nil {
		c.writeTimer.Stop()
		c.writeTimer = nil
	}
}

func (c *xhttpConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *xhttpConn) SetReadDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.readDeadline = t
	if c.readTimer != nil {
		c.readTimer.Stop()
		c.readTimer = nil
	}
	if !t.IsZero() {
		d := time.Until(t)
		if d <= 0 {
			c.deadlineMu.Unlock()
			c.expireReadDeadline()
			return nil
		}
		c.readTimer = time.AfterFunc(d, c.expireReadDeadline)
	}
	c.deadlineMu.Unlock()
	return nil
}

func (c *xhttpConn) SetWriteDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.writeDeadline = t
	if c.writeTimer != nil {
		c.writeTimer.Stop()
		c.writeTimer = nil
	}
	if !t.IsZero() {
		d := time.Until(t)
		if d <= 0 {
			c.deadlineMu.Unlock()
			c.expireWriteDeadline()
			return nil
		}
		c.writeTimer = time.AfterFunc(d, c.expireWriteDeadline)
	}
	c.deadlineMu.Unlock()
	return nil
}

func (c *xhttpConn) checkReadDeadline() error {
	c.deadlineMu.Lock()
	deadline := c.readDeadline
	c.deadlineMu.Unlock()
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return os.ErrDeadlineExceeded
	}
	return nil
}

func (c *xhttpConn) checkWriteDeadline() error {
	c.deadlineMu.Lock()
	deadline := c.writeDeadline
	c.deadlineMu.Unlock()
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return os.ErrDeadlineExceeded
	}
	return nil
}

func (c *xhttpConn) writeContext() (context.Context, context.CancelFunc, error) {
	c.deadlineMu.Lock()
	deadline := c.writeDeadline
	c.deadlineMu.Unlock()
	if !deadline.IsZero() {
		if !time.Now().Before(deadline) {
			return nil, nil, os.ErrDeadlineExceeded
		}
		ctx, cancel := context.WithDeadline(c.ctx, deadline)
		return ctx, cancel, nil
	}
	ctx, cancel := context.WithCancel(c.ctx)
	return ctx, cancel, nil
}

func (c *xhttpConn) expireReadDeadline() {
	if c.reader != nil {
		c.reader.closeWithError(os.ErrDeadlineExceeded)
	}
}

func (c *xhttpConn) expireWriteDeadline() {
	if c.uploadWriter != nil {
		_ = c.uploadWriter.CloseWithError(os.ErrDeadlineExceeded)
	}
}

type xhttpWaitReadCloser struct {
	ready chan struct{}
	once  sync.Once
	mu    sync.Mutex
	rc    io.ReadCloser
	err   error
}

func newXHTTPWaitReadCloser() *xhttpWaitReadCloser {
	return &xhttpWaitReadCloser{ready: make(chan struct{})}
}

func (w *xhttpWaitReadCloser) set(rc io.ReadCloser) {
	w.mu.Lock()
	if w.err != nil {
		w.mu.Unlock()
		_ = rc.Close()
		return
	}
	w.rc = rc
	w.mu.Unlock()
	w.once.Do(func() { close(w.ready) })
}

func (w *xhttpWaitReadCloser) closeWithError(err error) {
	if err == nil {
		err = io.ErrClosedPipe
	}
	w.mu.Lock()
	if w.err == nil {
		w.err = err
	}
	rc := w.rc
	w.mu.Unlock()
	if rc != nil {
		_ = rc.Close()
	}
	w.once.Do(func() { close(w.ready) })
}

func (w *xhttpWaitReadCloser) Read(p []byte) (int, error) {
	<-w.ready
	w.mu.Lock()
	rc := w.rc
	err := w.err
	w.mu.Unlock()
	if err != nil {
		return 0, err
	}
	if rc == nil {
		return 0, io.ErrClosedPipe
	}
	return rc.Read(p)
}

func (w *xhttpWaitReadCloser) waitReady(ctx context.Context) error {
	select {
	case <-w.ready:
		w.mu.Lock()
		err := w.err
		w.mu.Unlock()
		return err
	case <-ctx.Done():
		w.closeWithError(ctx.Err())
		return ctx.Err()
	}
}

func (w *xhttpWaitReadCloser) Close() error {
	w.closeWithError(io.ErrClosedPipe)
	return nil
}

func mapXHTTPDeadlineError(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return os.ErrDeadlineExceeded
	}
	return err
}
