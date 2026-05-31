package v2ray

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	_ "github.com/daeuniverse/outbound/protocol/vless"
	"golang.org/x/net/http2"
)

func vlessXHTTPTestURL(q url.Values) string {
	return "vless://00000000-0000-0000-0000-000000000000@example.com:443?" + q.Encode() + "#xhttp"
}

type xhttpRejectBeforeDialer struct {
	dialed bool
}

func (d *xhttpRejectBeforeDialer) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	d.dialed = true
	return nil, errors.New("unexpected XHTTP test network dial")
}

func assertXHTTPError(t *testing.T, err error, wantErr error, wantFields ...string) {
	t.Helper()
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want %v", err, wantErr)
	}
	for _, field := range wantFields {
		if !strings.Contains(err.Error(), field) {
			t.Fatalf("error = %v, want field %q", err, field)
		}
	}
}

func assertXHTTPRejectsBeforeDial(t *testing.T, q url.Values, wantErr error, wantFields ...string) {
	t.Helper()
	d := &xhttpRejectBeforeDialer{}
	_, _, err := NewV2Ray(&dialer.ExtraOption{}, d, vlessXHTTPTestURL(q))
	if d.dialed {
		t.Fatal("NewV2Ray dialed the network before rejecting unsupported XHTTP configuration")
	}
	assertXHTTPError(t, err, wantErr, wantFields...)
}

func TestXHTTPParseVLESSContract(t *testing.T) {
	q := url.Values{
		"type":     {"xhttp"},
		"security": {"tls"},
		"alpn":     {"h2,http/1.1"},
		"sni":      {"tls.example"},
		"host":     {"host.example"},
		"path":     {"api?token=1"},
		"mode":     {"stream-up"},
	}

	got, err := ParseVlessURL(vlessXHTTPTestURL(q))
	if err != nil {
		t.Fatalf("ParseVlessURL() error = %v", err)
	}
	if got.Net != "xhttp" {
		t.Fatalf("Net = %q, want xhttp", got.Net)
	}
	if got.XHTTP == nil {
		t.Fatal("XHTTP config is nil")
	}
	if got.XHTTP.Mode != XHTTPModeStreamUp || got.XHTTP.ResolvedMode != XHTTPModeStreamUp {
		t.Fatalf("mode = %q resolved = %q, want stream-up", got.XHTTP.Mode, got.XHTTP.ResolvedMode)
	}
	if got.XHTTP.Path != "/api/" || got.XHTTP.Query != "token=1" {
		t.Fatalf("path = %q query = %q, want /api/ and token=1", got.XHTTP.Path, got.XHTTP.Query)
	}
	if got.XHTTP.Host != "host.example" {
		t.Fatalf("host = %q, want explicit host", got.XHTTP.Host)
	}
	if got.XHTTP.ScMaxEachPostBytes != (XHTTPRange{From: xhttpDefaultScMaxEachPostBytes, To: xhttpDefaultScMaxEachPostBytes}) {
		t.Fatalf("ScMaxEachPostBytes = %+v, want default", got.XHTTP.ScMaxEachPostBytes)
	}
}

func TestSplitHTTPParseAliasDefaultsModeToAuto(t *testing.T) {
	q := url.Values{
		"type": {"splithttp"},
		"path": {"split"},
	}

	got, err := ParseVlessURL(vlessXHTTPTestURL(q))
	if err != nil {
		t.Fatalf("ParseVlessURL() error = %v", err)
	}
	if got.Net != "splithttp" {
		t.Fatalf("Net = %q, want splithttp", got.Net)
	}
	if got.XHTTP == nil {
		t.Fatal("XHTTP config is nil")
	}
	if got.XHTTP.Mode != XHTTPModeAuto {
		t.Fatalf("Mode = %q, want auto", got.XHTTP.Mode)
	}
	if got.XHTTP.ResolvedMode != XHTTPModePacketUp {
		t.Fatalf("ResolvedMode = %q, want packet-up", got.XHTTP.ResolvedMode)
	}
	if got.XHTTP.Path != "/split/" {
		t.Fatalf("Path = %q, want /split/", got.XHTTP.Path)
	}
}

func TestXHTTPValidateAutoModeResolution(t *testing.T) {
	tests := []struct {
		name     string
		security string
		alpn     string
		want     string
	}{
		{name: "no tls", security: "none", want: XHTTPModePacketUp},
		{name: "empty security", want: XHTTPModePacketUp},
		{name: "tls default alpn", security: "tls", want: XHTTPModeStreamUp},
		{name: "tls h2", security: "tls", alpn: "h2,http/1.1", want: XHTTPModeStreamUp},
		{name: "tls http11 only", security: "tls", alpn: "http/1.1", want: XHTTPModePacketUp},
		{name: "reality", security: "reality", want: XHTTPModeStreamOne},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ResolveXHTTPMode(XHTTPModeAuto, tt.security, tt.alpn)
			if err != nil {
				t.Fatalf("ResolveXHTTPMode() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("ResolveXHTTPMode() = %q, want %q", got, tt.want)
			}
		})
	}

	got, err := ResolveXHTTPMode(XHTTPModePacketUp, "tls", "h2")
	if err != nil {
		t.Fatalf("ResolveXHTTPMode(packet-up) error = %v", err)
	}
	if got != XHTTPModePacketUp {
		t.Fatalf("ResolveXHTTPMode(packet-up) = %q, want packet-up", got)
	}
}

func TestXHTTPValidatePathNormalization(t *testing.T) {
	tests := []struct {
		path      string
		wantPath  string
		wantQuery string
	}{
		{path: "", wantPath: "/"},
		{path: "/", wantPath: "/"},
		{path: "api", wantPath: "/api/"},
		{path: "/api", wantPath: "/api/"},
		{path: "/api/", wantPath: "/api/"},
		{path: "/api?token=1&ed=2048", wantPath: "/api/", wantQuery: "token=1&ed=2048"},
		{path: "?token=1", wantPath: "/", wantQuery: "token=1"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			gotPath, gotQuery := NormalizeXHTTPPath(tt.path)
			if gotPath != tt.wantPath || gotQuery != tt.wantQuery {
				t.Fatalf("NormalizeXHTTPPath(%q) = %q, %q; want %q, %q", tt.path, gotPath, gotQuery, tt.wantPath, tt.wantQuery)
			}
		})
	}
}

func TestXHTTPValidateHostPrecedence(t *testing.T) {
	tests := []struct {
		name       string
		host       string
		tlsSNI     string
		realitySNI string
		address    string
		want       string
	}{
		{name: "explicit host", host: "host.example", tlsSNI: "tls.example", realitySNI: "reality.example", address: "address.example", want: "host.example"},
		{name: "tls server name", tlsSNI: "tls.example", realitySNI: "reality.example", address: "address.example", want: "tls.example"},
		{name: "reality server name", realitySNI: "reality.example", address: "address.example", want: "reality.example"},
		{name: "address fallback", address: "address.example", want: "address.example"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ResolveXHTTPHost(tt.host, tt.tlsSNI, tt.realitySNI, tt.address)
			if got != tt.want {
				t.Fatalf("ResolveXHTTPHost() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestXHTTPPathEdgeNormalization(t *testing.T) {
	tests := []struct {
		name      string
		query     url.Values
		rawQuery  string
		wantPath  string
		wantQuery string
	}{
		{
			name:     "empty path",
			query:    url.Values{"type": {"xhttp"}},
			wantPath: "/",
		},
		{
			name:     "path without leading slash",
			query:    url.Values{"type": {"xhttp"}, "path": {"api"}},
			wantPath: "/api/",
		},
		{
			name:     "path without trailing slash",
			query:    url.Values{"type": {"xhttp"}, "path": {"/api"}},
			wantPath: "/api/",
		},
		{
			name:      "url encoded path and query",
			rawQuery:  "type=xhttp&path=%2Fencoded%2Fspace%2520name%3Ftoken%3Da%252Bb%26q%3Done%252Ftwo",
			wantPath:  "/encoded/space%20name/",
			wantQuery: "token=a%2Bb&q=one%2Ftwo",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rawQuery := tt.rawQuery
			if rawQuery == "" {
				rawQuery = tt.query.Encode()
			}
			link := "vless://00000000-0000-0000-0000-000000000000@example.com:443?" + rawQuery + "#xhttp"
			got, err := ParseVlessURL(link)
			if err != nil {
				t.Fatalf("ParseVlessURL() error = %v", err)
			}
			if got.XHTTP == nil {
				t.Fatal("XHTTP config is nil")
			}
			if got.XHTTP.Path != tt.wantPath || got.XHTTP.Query != tt.wantQuery {
				t.Fatalf("path = %q query = %q, want %q and %q", got.XHTTP.Path, got.XHTTP.Query, tt.wantPath, tt.wantQuery)
			}
		})
	}
}

func TestXHTTPHostEdgePrecedenceAndFallback(t *testing.T) {
	tests := []struct {
		name         string
		link         string
		query        url.Values
		wantAddress  string
		wantSNI      string
		wantHost     string
		wantResolved string
	}{
		{
			name: "explicit host different from sni",
			query: url.Values{
				"type":     {"xhttp"},
				"security": {"tls"},
				"sni":      {"sni.example"},
				"host":     {"host.example"},
			},
			wantAddress:  "example.com",
			wantSNI:      "sni.example",
			wantHost:     "host.example",
			wantResolved: XHTTPModeStreamUp,
		},
		{
			name: "reality serverName fallback when sni absent",
			query: url.Values{
				"type":       {"xhttp"},
				"security":   {"reality"},
				"serverName": {"reality.example"},
			},
			wantAddress:  "example.com",
			wantSNI:      "reality.example",
			wantHost:     "reality.example",
			wantResolved: XHTTPModeStreamOne,
		},
		{
			name:         "ipv6 address fallback",
			link:         "vless://00000000-0000-0000-0000-000000000000@[2001:db8::1]:443?type=xhttp&security=none#xhttp",
			wantAddress:  "2001:db8::1",
			wantHost:     "2001:db8::1",
			wantResolved: XHTTPModePacketUp,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			link := tt.link
			if link == "" {
				link = vlessXHTTPTestURL(tt.query)
			}
			got, err := ParseVlessURL(link)
			if err != nil {
				t.Fatalf("ParseVlessURL() error = %v", err)
			}
			if got.XHTTP == nil {
				t.Fatal("XHTTP config is nil")
			}
			if got.Add != tt.wantAddress {
				t.Fatalf("Add = %q, want %q", got.Add, tt.wantAddress)
			}
			if got.SNI != tt.wantSNI {
				t.Fatalf("SNI = %q, want %q", got.SNI, tt.wantSNI)
			}
			if got.XHTTP.Host != tt.wantHost {
				t.Fatalf("XHTTP.Host = %q, want %q", got.XHTTP.Host, tt.wantHost)
			}
			if got.XHTTP.ResolvedMode != tt.wantResolved {
				t.Fatalf("ResolvedMode = %q, want %q", got.XHTTP.ResolvedMode, tt.wantResolved)
			}
		})
	}
}

func TestXHTTPTransportIPv6URLHostFormatting(t *testing.T) {
	if got := xhttpURLHost("2001:db8::1"); got != "[2001:db8::1]" {
		t.Fatalf("xhttpURLHost(IPv6) = %q, want bracketed IPv6", got)
	}
	if got := xhttpURLHost("[2001:db8::1]"); got != "[2001:db8::1]" {
		t.Fatalf("xhttpURLHost(bracketed IPv6) = %q, want unchanged", got)
	}
	if got := xhttpURLHost("example.com"); got != "example.com" {
		t.Fatalf("xhttpURLHost(domain) = %q, want example.com", got)
	}
}

func TestXHTTPEdgeDuplicateQueryParametersUseFirstValue(t *testing.T) {
	link := "vless://00000000-0000-0000-0000-000000000000@example.com:443?" + strings.Join([]string{
		"type=xhttp",
		"path=first",
		"path=second",
		"mode=stream-up",
		"mode=packet-up",
		"host=first.example",
		"host=second.example",
		"extra=" + url.QueryEscape(`{"xPaddingBytes":32}`),
		"extra=" + url.QueryEscape(`{"xPaddingBytes":64}`),
	}, "&") + "#xhttp"

	got, err := ParseVlessURL(link)
	if err != nil {
		t.Fatalf("ParseVlessURL() error = %v", err)
	}
	if got.XHTTP == nil {
		t.Fatal("XHTTP config is nil")
	}
	if got.XHTTP.Path != "/first/" {
		t.Fatalf("Path = %q, want /first/", got.XHTTP.Path)
	}
	if got.XHTTP.Mode != XHTTPModeStreamUp || got.XHTTP.ResolvedMode != XHTTPModeStreamUp {
		t.Fatalf("Mode = %q resolved = %q, want stream-up", got.XHTTP.Mode, got.XHTTP.ResolvedMode)
	}
	if got.XHTTP.Host != "first.example" {
		t.Fatalf("Host = %q, want first.example", got.XHTTP.Host)
	}
	if got.XHTTP.XPaddingBytes != (XHTTPRange{From: 32, To: 32}) {
		t.Fatalf("XPaddingBytes = %+v, want first duplicate value 32", got.XHTTP.XPaddingBytes)
	}
}

func TestXHTTPEdgeSupportedExtraSubset(t *testing.T) {
	tests := []struct {
		name     string
		extra    string
		wantMode string
		wantSc   XHTTPRange
		wantPad  XHTTPRange
	}{
		{
			name:     "extra mode",
			extra:    `{"mode":"stream-one"}`,
			wantMode: XHTTPModeStreamOne,
		},
		{
			name:   "scMaxEachPostBytes numeric",
			extra:  `{"scMaxEachPostBytes":256}`,
			wantSc: XHTTPRange{From: 256, To: 256},
		},
		{
			name:   "scMaxEachPostBytes range",
			extra:  `{"scMaxEachPostBytes":"128-256"}`,
			wantSc: XHTTPRange{From: 128, To: 256},
		},
		{
			name:    "xPaddingBytes numeric",
			extra:   `{"xPaddingBytes":64}`,
			wantPad: XHTTPRange{From: 64, To: 64},
		},
		{
			name:    "xPaddingBytes range",
			extra:   `{"xPaddingBytes":"100-1000"}`,
			wantPad: XHTTPRange{From: 100, To: 1000},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseVlessURL(vlessXHTTPTestURL(url.Values{"type": {"xhttp"}, "extra": {tt.extra}}))
			if err != nil {
				t.Fatalf("ParseVlessURL() error = %v", err)
			}
			if got.XHTTP == nil {
				t.Fatal("XHTTP config is nil")
			}
			wantMode := tt.wantMode
			if wantMode == "" {
				wantMode = XHTTPModeAuto
			}
			if got.XHTTP.Mode != wantMode {
				t.Fatalf("Mode = %q, want %q", got.XHTTP.Mode, wantMode)
			}
			if !tt.wantSc.IsZero() && got.XHTTP.ScMaxEachPostBytes != tt.wantSc {
				t.Fatalf("ScMaxEachPostBytes = %+v, want %+v", got.XHTTP.ScMaxEachPostBytes, tt.wantSc)
			}
			if !tt.wantPad.IsZero() && got.XHTTP.XPaddingBytes != tt.wantPad {
				t.Fatalf("XPaddingBytes = %+v, want %+v", got.XHTTP.XPaddingBytes, tt.wantPad)
			}
		})
	}
}

func TestXHTTPParseExtra(t *testing.T) {
	q := url.Values{
		"type":  {"xhttp"},
		"path":  {"/extra"},
		"extra": {`{"mode":"stream-one","scMaxEachPostBytes":"128-256","xPaddingBytes":64}`},
	}

	got, err := ParseVlessURL(vlessXHTTPTestURL(q))
	if err != nil {
		t.Fatalf("ParseVlessURL() error = %v", err)
	}
	if got.XHTTP == nil {
		t.Fatal("XHTTP config is nil")
	}
	if got.XHTTP.Mode != XHTTPModeStreamOne || got.XHTTP.ResolvedMode != XHTTPModeStreamOne {
		t.Fatalf("mode = %q resolved = %q, want stream-one", got.XHTTP.Mode, got.XHTTP.ResolvedMode)
	}
	if got.XHTTP.ScMaxEachPostBytes != (XHTTPRange{From: 128, To: 256}) {
		t.Fatalf("ScMaxEachPostBytes = %+v, want 128-256", got.XHTTP.ScMaxEachPostBytes)
	}
	if got.XHTTP.XPaddingBytes != (XHTTPRange{From: 64, To: 64}) {
		t.Fatalf("XPaddingBytes = %+v, want 64", got.XHTTP.XPaddingBytes)
	}
}

func TestXHTTPParseInvalidMode(t *testing.T) {
	q := url.Values{
		"type": {"xhttp"},
		"mode": {"stream-two"},
	}

	_, err := ParseVlessURL(vlessXHTTPTestURL(q))
	if !errors.Is(err, dialer.InvalidParameterErr) {
		t.Fatalf("ParseVlessURL() error = %v, want InvalidParameterErr", err)
	}
}

func TestXHTTPParseInvalidExtraMode(t *testing.T) {
	q := url.Values{
		"type":  {"xhttp"},
		"mode":  {"auto"},
		"extra": {`{"mode":"stream-two"}`},
	}

	_, err := ParseVlessURL(vlessXHTTPTestURL(q))
	if !errors.Is(err, dialer.InvalidParameterErr) {
		t.Fatalf("ParseVlessURL() error = %v, want InvalidParameterErr", err)
	}
	if !strings.Contains(err.Error(), "extra.mode") {
		t.Fatalf("ParseVlessURL() error = %v, want extra.mode", err)
	}
}

func TestXHTTPParseMismatchedExtraMode(t *testing.T) {
	q := url.Values{
		"type":  {"xhttp"},
		"mode":  {"auto"},
		"extra": {`{"mode":"stream-up"}`},
	}

	_, err := ParseVlessURL(vlessXHTTPTestURL(q))
	if !errors.Is(err, dialer.InvalidParameterErr) {
		t.Fatalf("ParseVlessURL() error = %v, want InvalidParameterErr", err)
	}
	if !strings.Contains(err.Error(), "extra.mode") || !strings.Contains(err.Error(), "mode") {
		t.Fatalf("ParseVlessURL() error = %v, want extra.mode and mode", err)
	}
}

func TestXHTTPParseMatchingExtraMode(t *testing.T) {
	q := url.Values{
		"type":  {"xhttp"},
		"mode":  {"stream-up"},
		"extra": {`{"mode":"stream-up","xPaddingBytes":"100-1000"}`},
	}

	got, err := ParseVlessURL(vlessXHTTPTestURL(q))
	if err != nil {
		t.Fatalf("ParseVlessURL() error = %v", err)
	}
	if got.XHTTP == nil {
		t.Fatal("XHTTP config is nil")
	}
	if got.XHTTP.Mode != XHTTPModeStreamUp || got.XHTTP.ResolvedMode != XHTTPModeStreamUp {
		t.Fatalf("mode = %q resolved = %q, want stream-up", got.XHTTP.Mode, got.XHTTP.ResolvedMode)
	}
	if got.XHTTP.XPaddingBytes != (XHTTPRange{From: 100, To: 1000}) {
		t.Fatalf("XPaddingBytes = %+v, want 100-1000", got.XHTTP.XPaddingBytes)
	}
}

func TestXHTTPParseUnsupportedFields(t *testing.T) {
	tests := []struct {
		name      string
		query     url.Values
		wantErr   error
		wantField string
	}{
		{
			name: "headers host",
			query: url.Values{
				"type":         {"xhttp"},
				"headers.host": {"forbidden.example"},
			},
			wantErr:   dialer.UnexpectedFieldErr,
			wantField: "headers.host",
		},
		{
			name: "download settings",
			query: url.Values{
				"type":             {"xhttp"},
				"downloadSettings": {`{"network":"tcp"}`},
			},
			wantErr:   dialer.UnexpectedFieldErr,
			wantField: "downloadSettings",
		},
		{
			name: "top level range",
			query: url.Values{
				"type":               {"xhttp"},
				"scMaxEachPostBytes": {"128"},
			},
			wantErr:   dialer.UnexpectedFieldErr,
			wantField: "scMaxEachPostBytes",
		},
		{
			name: "h3 alpn",
			query: url.Values{
				"type": {"xhttp"},
				"alpn": {"h3"},
			},
			wantErr:   dialer.UnexpectedFieldErr,
			wantField: "alpn",
		},
		{
			name: "extra unsupported xmux",
			query: url.Values{
				"type":  {"xhttp"},
				"extra": {`{"xmux":{"maxConcurrency":1}}`},
			},
			wantErr:   dialer.UnexpectedFieldErr,
			wantField: "extra.xmux",
		},
		{
			name: "extra malformed",
			query: url.Values{
				"type":  {"xhttp"},
				"extra": {`{"mode":`},
			},
			wantErr:   dialer.InvalidParameterErr,
			wantField: "extra",
		},
		{
			name: "extra disabled padding",
			query: url.Values{
				"type":  {"xhttp"},
				"extra": {`{"xPaddingBytes":0}`},
			},
			wantErr:   dialer.InvalidParameterErr,
			wantField: "xPaddingBytes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseVlessURL(vlessXHTTPTestURL(tt.query))
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("ParseVlessURL() error = %v, want %v", err, tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantField) {
				t.Fatalf("ParseVlessURL() error = %v, want field %q", err, tt.wantField)
			}
		})
	}
}

func TestXHTTPRejectUnsupportedAdvancedOptionsBeforeDial(t *testing.T) {
	tests := []struct {
		name      string
		query     url.Values
		wantErr   error
		wantField string
	}{
		{
			name: "unsupported mode casing",
			query: url.Values{
				"type": {"xhttp"},
				"mode": {"Stream-Up"},
			},
			wantErr:   dialer.InvalidParameterErr,
			wantField: "xhttp mode",
		},
		{
			name: "unsupported h3 alpn",
			query: url.Values{
				"type": {"xhttp"},
				"alpn": {"h2,h3"},
			},
			wantErr:   dialer.UnexpectedFieldErr,
			wantField: "alpn",
		},
		{
			name: "unsupported quic alpn",
			query: url.Values{
				"type": {"xhttp"},
				"alpn": {"quic"},
			},
			wantErr:   dialer.UnexpectedFieldErr,
			wantField: "alpn",
		},
		{
			name: "unsupported downloadSettings",
			query: url.Values{
				"type":             {"xhttp"},
				"downloadSettings": {`{"network":"tcp"}`},
			},
			wantErr:   dialer.UnexpectedFieldErr,
			wantField: "downloadSettings",
		},
		{
			name: "unsupported browserDialer",
			query: url.Values{
				"type":          {"xhttp"},
				"browserDialer": {"true"},
			},
			wantErr:   dialer.UnexpectedFieldErr,
			wantField: "browserDialer",
		},
		{
			name: "unsupported BrowserDialer casing",
			query: url.Values{
				"type":          {"xhttp"},
				"BrowserDialer": {"wss://browser.example/dial"},
			},
			wantErr:   dialer.UnexpectedFieldErr,
			wantField: "BrowserDialer",
		},
		{
			name: "unsupported top headers",
			query: url.Values{
				"type":    {"xhttp"},
				"headers": {`{"User-Agent":"dae"}`},
			},
			wantErr:   dialer.UnexpectedFieldErr,
			wantField: "headers",
		},
		{
			name: "unsupported top scMaxEachPostBytes",
			query: url.Values{
				"type":               {"xhttp"},
				"scMaxEachPostBytes": {"128-256"},
			},
			wantErr:   dialer.UnexpectedFieldErr,
			wantField: "scMaxEachPostBytes",
		},
		{
			name: "unsupported top xPaddingBytes",
			query: url.Values{
				"type":          {"xhttp"},
				"xPaddingBytes": {"100-1000"},
			},
			wantErr:   dialer.UnexpectedFieldErr,
			wantField: "xPaddingBytes",
		},
		{
			name: "unsupported noGRPCHeader",
			query: url.Values{
				"type":         {"xhttp"},
				"noGRPCHeader": {"true"},
			},
			wantErr:   dialer.UnexpectedFieldErr,
			wantField: "noGRPCHeader",
		},
		{
			name: "unsupported noSSEHeader",
			query: url.Values{
				"type":        {"xhttp"},
				"noSSEHeader": {"true"},
			},
			wantErr:   dialer.UnexpectedFieldErr,
			wantField: "noSSEHeader",
		},
		{
			name: "unsupported scMinPostsIntervalMs",
			query: url.Values{
				"type":                 {"xhttp"},
				"scMinPostsIntervalMs": {"30-60"},
			},
			wantErr:   dialer.UnexpectedFieldErr,
			wantField: "scMinPostsIntervalMs",
		},
		{
			name: "unsupported scMaxBufferedPosts",
			query: url.Values{
				"type":               {"xhttp"},
				"scMaxBufferedPosts": {"8"},
			},
			wantErr:   dialer.UnexpectedFieldErr,
			wantField: "scMaxBufferedPosts",
		},
		{
			name: "unsupported scStreamUpServerSecs",
			query: url.Values{
				"type":                 {"xhttp"},
				"scStreamUpServerSecs": {"20-80"},
			},
			wantErr:   dialer.UnexpectedFieldErr,
			wantField: "scStreamUpServerSecs",
		},
		{
			name: "unsupported full xmux",
			query: url.Values{
				"type": {"xhttp"},
				"xmux": {`{"maxConcurrency":"1-4","hMaxRequestTimes":"600-900"}`},
			},
			wantErr:   dialer.UnexpectedFieldErr,
			wantField: "xmux",
		},
		{
			name: "unsupported xmux dotted field",
			query: url.Values{
				"type":                {"xhttp"},
				"xmux.maxConcurrency": {"1-4"},
			},
			wantErr:   dialer.UnexpectedFieldErr,
			wantField: "xmux.maxConcurrency",
		},
		{
			name: "unsupported extra headers",
			query: url.Values{
				"type":  {"xhttp"},
				"extra": {`{"headers":{"User-Agent":"dae"}}`},
			},
			wantErr:   dialer.UnexpectedFieldErr,
			wantField: "extra.headers",
		},
		{
			name: "unsupported extra downloadSettings",
			query: url.Values{
				"type":  {"xhttp"},
				"extra": {`{"downloadSettings":{"network":"tcp"}}`},
			},
			wantErr:   dialer.UnexpectedFieldErr,
			wantField: "extra.downloadSettings",
		},
		{
			name: "unsupported extra noGRPCHeader",
			query: url.Values{
				"type":  {"xhttp"},
				"extra": {`{"noGRPCHeader":true}`},
			},
			wantErr:   dialer.UnexpectedFieldErr,
			wantField: "extra.noGRPCHeader",
		},
		{
			name: "unsupported extra noSSEHeader",
			query: url.Values{
				"type":  {"xhttp"},
				"extra": {`{"noSSEHeader":true}`},
			},
			wantErr:   dialer.UnexpectedFieldErr,
			wantField: "extra.noSSEHeader",
		},
		{
			name: "unsupported extra xmux",
			query: url.Values{
				"type":  {"xhttp"},
				"extra": {`{"xmux":{"maxConcurrency":1}}`},
			},
			wantErr:   dialer.UnexpectedFieldErr,
			wantField: "extra.xmux",
		},
		{
			name: "unsupported extra scMinPostsIntervalMs",
			query: url.Values{
				"type":  {"xhttp"},
				"extra": {`{"scMinPostsIntervalMs":"30-60"}`},
			},
			wantErr:   dialer.UnexpectedFieldErr,
			wantField: "extra.scMinPostsIntervalMs",
		},
		{
			name: "unsupported extra scMaxBufferedPosts",
			query: url.Values{
				"type":  {"xhttp"},
				"extra": {`{"scMaxBufferedPosts":8}`},
			},
			wantErr:   dialer.UnexpectedFieldErr,
			wantField: "extra.scMaxBufferedPosts",
		},
		{
			name: "unsupported extra scStreamUpServerSecs",
			query: url.Values{
				"type":  {"xhttp"},
				"extra": {`{"scStreamUpServerSecs":"20-80"}`},
			},
			wantErr:   dialer.UnexpectedFieldErr,
			wantField: "extra.scStreamUpServerSecs",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertXHTTPRejectsBeforeDial(t, tt.query, tt.wantErr, tt.wantField)
		})
	}
}

func TestXHTTPRejectHeadersHostVariantsBeforeDial(t *testing.T) {
	tests := []struct {
		name  string
		query url.Values
		field string
	}{
		{
			name: "lowercase headers.host",
			query: url.Values{
				"type":         {"xhttp"},
				"headers.host": {"forbidden.example"},
			},
			field: "headers.host",
		},
		{
			name: "uppercase Headers.Host",
			query: url.Values{
				"type":         {"xhttp"},
				"Headers.Host": {"forbidden.example"},
			},
			field: "Headers.Host",
		},
		{
			name: "extra headers host object",
			query: url.Values{
				"type":  {"xhttp"},
				"extra": {`{"headers":{"Host":"forbidden.example"}}`},
			},
			field: "extra.headers",
		},
		{
			name: "top headers Host object",
			query: url.Values{
				"type":    {"xhttp"},
				"headers": {`{"Host":"forbidden.example"}`},
			},
			field: "headers",
		},
		{
			name: "extra headers lowercase host object",
			query: url.Values{
				"type":  {"xhttp"},
				"extra": {`{"headers":{"host":"forbidden.example"}}`},
			},
			field: "extra.headers",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertXHTTPRejectsBeforeDial(t, tt.query, dialer.UnexpectedFieldErr, tt.field)
		})
	}
}

func TestVMessXHTTPUnsupportedBeforeDial(t *testing.T) {
	for _, networkType := range []string{"xhttp", "splithttp"} {
		t.Run(networkType, func(t *testing.T) {
			vmess := `{"v":"2","ps":"xhttp","add":"example.com","port":"443","id":"00000000-0000-0000-0000-000000000000","aid":"0","net":"` + networkType + `","type":"none","tls":"tls"}`
			link := "vmess://" + strings.TrimRight(base64.StdEncoding.EncodeToString([]byte(vmess)), "=")

			_, err := ParseVmessURL(link)
			if !errors.Is(err, dialer.UnexpectedFieldErr) {
				t.Fatalf("ParseVmessURL() error = %v, want UnexpectedFieldErr", err)
			}
			if !strings.Contains(err.Error(), "network: "+networkType) {
				t.Fatalf("ParseVmessURL() error = %v, want network %q", err, networkType)
			}

			_, _, err = NewV2Ray(&dialer.ExtraOption{}, xhttpServerDialer{addr: "127.0.0.1:1"}, link)
			if !errors.Is(err, dialer.UnexpectedFieldErr) {
				t.Fatalf("NewV2Ray() error = %v, want UnexpectedFieldErr", err)
			}
		})
	}
}

type xhttpRecordedRequest struct {
	Method        string
	Path          string
	RawQuery      string
	Host          string
	Proto         string
	ContentType   string
	Referer       string
	Body          string
	ContentLength int64
}

type xhttpRequestRecorder struct {
	mu       sync.Mutex
	requests []xhttpRecordedRequest
	seen     chan struct{}
}

func newXHTTPRequestRecorder() *xhttpRequestRecorder {
	return &xhttpRequestRecorder{seen: make(chan struct{}, 16)}
}

func (r *xhttpRequestRecorder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	body, _ := io.ReadAll(req.Body)
	_ = req.Body.Close()
	r.mu.Lock()
	r.requests = append(r.requests, xhttpRecordedRequest{
		Method:        req.Method,
		Path:          req.URL.Path,
		RawQuery:      req.URL.RawQuery,
		Host:          req.Host,
		Proto:         req.Proto,
		ContentType:   req.Header.Get("Content-Type"),
		Referer:       req.Header.Get("Referer"),
		Body:          string(body),
		ContentLength: req.ContentLength,
	})
	r.mu.Unlock()
	select {
	case r.seen <- struct{}{}:
	default:
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte{0, 0})
}

func (r *xhttpRequestRecorder) waitFor(t *testing.T, count int) []xhttpRecordedRequest {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		r.mu.Lock()
		if len(r.requests) >= count {
			requests := append([]xhttpRecordedRequest(nil), r.requests...)
			r.mu.Unlock()
			return requests
		}
		r.mu.Unlock()
		select {
		case <-r.seen:
		case <-deadline:
			r.mu.Lock()
			requests := append([]xhttpRecordedRequest(nil), r.requests...)
			r.mu.Unlock()
			t.Fatalf("timed out waiting for %d XHTTP requests; got %d: %+v", count, len(requests), requests)
		}
	}
}

func (r *xhttpRequestRecorder) waitForMethod(t *testing.T, method string) xhttpRecordedRequest {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		r.mu.Lock()
		for _, req := range r.requests {
			if req.Method == method {
				r.mu.Unlock()
				return req
			}
		}
		r.mu.Unlock()
		select {
		case <-r.seen:
		case <-deadline:
			r.mu.Lock()
			requests := append([]xhttpRecordedRequest(nil), r.requests...)
			r.mu.Unlock()
			t.Fatalf("timed out waiting for XHTTP %s request; got %d: %+v", method, len(requests), requests)
		}
	}
}

type xhttpServerDialer struct {
	addr string
}

func (d xhttpServerDialer) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	var nd net.Dialer
	return nd.DialContext(ctx, "tcp", d.addr)
}

func newXHTTPTestDialer(t *testing.T, serverURL string, cfg *XHTTPConfig, security, alpn string) netproxy.Dialer {
	t.Helper()
	u, err := url.Parse(serverURL)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", serverURL, err)
	}
	serverHost, serverPort, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatalf("net.SplitHostPort(%q): %v", u.Host, err)
	}
	s := &V2Ray{
		Add:           serverHost,
		Port:          serverPort,
		ID:            "00000000-0000-0000-0000-000000000000",
		Net:           "xhttp",
		Host:          "xhttp.example",
		SNI:           "xhttp.example",
		TLS:           security,
		Alpn:          alpn,
		AllowInsecure: true,
		Protocol:      "vless",
		XHTTP:         cfg,
	}
	if security == "none" || security == "" {
		s.TLS = "none"
	}
	if cfg.Host == "" {
		cfg.Host = "xhttp.example"
	}
	d, err := newXHTTPDialer(&dialer.ExtraOption{AllowInsecure: true}, xhttpServerDialer{addr: u.Host}, s)
	if err != nil {
		t.Fatalf("newXHTTPDialer() error = %v", err)
	}
	return d
}

func xhttpTestConfig(mode string) *XHTTPConfig {
	return &XHTTPConfig{
		Mode:               mode,
		ResolvedMode:       mode,
		Host:               "xhttp.example",
		Path:               "/api/",
		Query:              "token=1",
		ScMaxEachPostBytes: XHTTPRange{From: xhttpDefaultScMaxEachPostBytes, To: xhttpDefaultScMaxEachPostBytes},
	}
}

func TestXHTTPTransportPacketUpRequestShapesAndChunkSizing(t *testing.T) {
	recorder := newXHTTPRequestRecorder()
	server := httptest.NewServer(recorder)
	defer server.Close()

	cfg := xhttpTestConfig(XHTTPModePacketUp)
	cfg.ScMaxEachPostBytes = XHTTPRange{From: 4, To: 4}
	cfg.XPaddingBytes = XHTTPRange{From: 12, To: 12}
	d := newXHTTPTestDialer(t, server.URL, cfg, "none", "")

	conn, err := d.DialContext(context.Background(), "tcp", "target.example:443")
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("abcdefghi")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	requests := recorder.waitFor(t, 4)
	for _, req := range requests {
		if req.Host != "xhttp.example" {
			t.Fatalf("Host = %q, want xhttp.example in requests %+v", req.Host, requests)
		}
		if req.Proto != "HTTP/1.1" {
			t.Fatalf("request proto = %q, want HTTP/1.1 in requests %+v", req.Proto, requests)
		}
	}
	var gets, posts []xhttpRecordedRequest
	for _, req := range requests {
		switch req.Method {
		case http.MethodGet:
			gets = append(gets, req)
		case http.MethodPost:
			posts = append(posts, req)
		}
	}
	if len(gets) != 1 || len(posts) != 3 {
		t.Fatalf("got %d GET and %d POST requests, want 1 GET and 3 POST: %+v", len(gets), len(posts), requests)
	}
	sessionPath := gets[0].Path
	if !strings.HasPrefix(sessionPath, "/api/") || strings.Count(strings.TrimPrefix(sessionPath, "/api/"), "/") != 0 {
		t.Fatalf("download GET path = %q, want /api/{uuid}", sessionPath)
	}
	if gets[0].RawQuery != "token=1" {
		t.Fatalf("GET query = %q, want token=1", gets[0].RawQuery)
	}
	sort.Slice(posts, func(i, j int) bool { return posts[i].Path < posts[j].Path })
	wantBodies := []string{"abcd", "efgh", "i"}
	for i, req := range posts {
		wantPath := sessionPath + "/" + strconv.Itoa(i)
		if req.Path != wantPath {
			t.Fatalf("POST[%d] path = %q, want %q", i, req.Path, wantPath)
		}
		if req.RawQuery != "token=1" {
			t.Fatalf("POST[%d] query = %q, want token=1", i, req.RawQuery)
		}
		if req.Body != wantBodies[i] {
			t.Fatalf("POST[%d] body = %q, want %q", i, req.Body, wantBodies[i])
		}
		if req.ContentLength > 4 {
			t.Fatalf("POST[%d] ContentLength = %d, want <= 4", i, req.ContentLength)
		}
		assertXHTTPRefererPadding(t, req.Referer, 12, 12)
	}
	assertXHTTPRefererPadding(t, gets[0].Referer, 12, 12)
}

func TestVLESSXHTTPDialerConstruction(t *testing.T) {
	for _, networkType := range []string{"xhttp", "splithttp"} {
		t.Run(networkType, func(t *testing.T) {
			recorder := newXHTTPRequestRecorder()
			server := httptest.NewServer(recorder)
			defer server.Close()
			u, err := url.Parse(server.URL)
			if err != nil {
				t.Fatalf("url.Parse(%q): %v", server.URL, err)
			}
			link := "vless://00000000-0000-0000-0000-000000000000@" + u.Host + "?" + url.Values{
				"type":     {networkType},
				"security": {"none"},
				"path":     {"/api"},
				"mode":     {"packet-up"},
			}.Encode()
			v, err := ParseVlessURL(link)
			if err != nil {
				t.Fatalf("ParseVlessURL() error = %v", err)
			}
			d, property, err := v.Dialer(&dialer.ExtraOption{}, xhttpServerDialer{addr: u.Host})
			if err != nil {
				t.Fatalf("V2Ray.Dialer() error = %v", err)
			}
			if d == nil || property == nil {
				t.Fatalf("V2Ray.Dialer() returned dialer=%v property=%v, want non-nil", d, property)
			}
			if got := property.Link; strings.HasPrefix(got, "xhttp://") || !strings.HasPrefix(got, "vless://") {
				t.Fatalf("property.Link = %q, want vless:// link and no xhttp:// scheme", got)
			}
			if property.Protocol != "vless" {
				t.Fatalf("property.Protocol = %q, want vless", property.Protocol)
			}
			conn, err := d.DialContext(context.Background(), "tcp", "target.example:443")
			if err != nil {
				t.Fatalf("DialContext() error = %v", err)
			}
			defer conn.Close()
			requests := recorder.waitFor(t, 1)
			lastReq := requests[len(requests)-1]
			if lastReq.Method != http.MethodGet {
				t.Fatalf("XHTTP request method = %q, want GET in requests %+v", lastReq.Method, requests)
			}
			if !strings.HasPrefix(lastReq.Path, "/api/") {
				t.Fatalf("XHTTP request path = %q, want /api/{uuid}", lastReq.Path)
			}
		})
	}
}

func TestVLESSExistingTransportConstructionAndExport(t *testing.T) {
	tests := []struct {
		name       string
		query      url.Values
		wantExport map[string]string
		wantAbsent []string
		dial       bool
	}{
		{
			name: "tcp",
			query: url.Values{
				"type":       {"tcp"},
				"headerType": {"none"},
			},
			wantExport: map[string]string{"type": "tcp", "headerType": "none"},
			wantAbsent: []string{"pbk", "sid", "spx", "pqv"},
			dial:       true,
		},
		{
			name: "ws",
			query: url.Values{
				"type": {"ws"},
				"host": {"ws.example"},
				"path": {"/websocket"},
			},
			wantExport: map[string]string{"type": "ws", "host": "ws.example", "path": "/websocket"},
			wantAbsent: []string{"pbk", "sid", "spx", "pqv"},
			dial:       true,
		},
		{
			name: "grpc",
			query: url.Values{
				"type":        {"grpc"},
				"serviceName": {"GunService"},
			},
			wantExport: map[string]string{"type": "grpc", "serviceName": "GunService"},
			wantAbsent: []string{"pbk", "sid", "spx", "pqv"},
			dial:       true,
		},
		{
			name: "h2",
			query: url.Values{
				"type": {"h2"},
				"host": {"h2.example"},
				"path": {"/h2"},
			},
			wantExport: map[string]string{"type": "h2", "host": "h2.example", "path": "/h2"},
			wantAbsent: []string{"pbk", "sid", "spx", "pqv"},
			dial:       true,
		},
		{
			name: "http",
			query: url.Values{
				"type": {"http"},
				"host": {"http.example"},
				"path": {"/http"},
			},
			wantExport: map[string]string{"type": "http", "host": "http.example", "path": "/http"},
			wantAbsent: []string{"pbk", "sid", "spx", "pqv"},
			dial:       true,
		},
		{
			name: "httpupgrade",
			query: url.Values{
				"type": {"httpupgrade"},
				"host": {"upgrade.example"},
				"path": {"/upgrade"},
			},
			wantExport: map[string]string{"type": "httpupgrade", "host": "upgrade.example", "path": "/upgrade"},
			wantAbsent: []string{"pbk", "sid", "spx", "pqv"},
			dial:       true,
		},
		{
			name: "tls-no-reality-fields",
			query: url.Values{
				"type":     {"tcp"},
				"security": {"tls"},
				"sni":      {"tls.example"},
				"alpn":     {"h2"},
				"flow":     {"xtls-rprx-vision"},
				"fp":       {"chrome"},
				"pbk":      {"should-not-export-pbk"},
				"sid":      {"should-not-export-sid"},
				"spx":      {"should-not-export-spx"},
				"pqv":      {"should-not-export-pqv"},
			},
			wantExport: map[string]string{"type": "tcp", "security": "tls", "sni": "tls.example", "alpn": "h2", "flow": "xtls-rprx-vision", "fp": "chrome"},
			wantAbsent: []string{"pbk", "sid", "spx", "pqv"},
			dial:       true,
		},
		{
			name: "tcp-reality-roundtrip",
			query: url.Values{
				"type":       {"tcp"},
				"security":   {"reality"},
				"headerType": {"none"},
				"sni":        {"reality.example"},
				"alpn":       {"h2,http/1.1"},
				"flow":       {"xtls-rprx-vision"},
				"fp":         {"chrome"},
				"pbk":        {"public-key-value"},
				"sid":        {"shortid-value"},
				"spx":        {"spider-x-value"},
				"pqv":        {"mldsa65-verify-value"},
			},
			wantExport: map[string]string{"type": "tcp", "security": "reality", "headerType": "none", "sni": "reality.example", "alpn": "h2,http/1.1", "flow": "xtls-rprx-vision", "fp": "chrome", "pbk": "public-key-value", "sid": "shortid-value", "spx": "spider-x-value", "pqv": "mldsa65-verify-value"},
			dial:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			link := "vless://00000000-0000-0000-0000-000000000000@example.com:443?" + tt.query.Encode() + "#" + tt.name
			v, err := ParseVlessURL(link)
			if err != nil {
				t.Fatalf("ParseVlessURL() error = %v", err)
			}
			exportedLink := v.ExportToURL()
			if tt.dial {
				d, property, err := v.Dialer(&dialer.ExtraOption{}, xhttpServerDialer{addr: "127.0.0.1:1"})
				if err != nil {
					t.Fatalf("V2Ray.Dialer() error = %v", err)
				}
				if d == nil || property == nil {
					t.Fatalf("V2Ray.Dialer() returned dialer=%v property=%v, want non-nil", d, property)
				}
				if property.Protocol != "vless" || property.Address != "example.com:443" {
					t.Fatalf("property = %+v, want vless example.com:443", property)
				}
				if strings.HasPrefix(property.Link, "xhttp://") {
					t.Fatalf("property.Link = %q, must not use xhttp:// scheme", property.Link)
				}
				exportedLink = property.Link
			}
			exported, err := url.Parse(exportedLink)
			if err != nil {
				t.Fatalf("url.Parse(exported link %q): %v", exportedLink, err)
			}
			if exported.Scheme != "vless" {
				t.Fatalf("exported scheme = %q, want vless", exported.Scheme)
			}
			for key, want := range tt.wantExport {
				if got := exported.Query().Get(key); got != want {
					t.Fatalf("exported query %s = %q, want %q in %q", key, got, want, exportedLink)
				}
			}
			for _, key := range tt.wantAbsent {
				if got := exported.Query().Get(key); got != "" {
					t.Fatalf("exported query %s = %q, want empty in %q", key, got, exportedLink)
				}
			}
		})
	}
}

func TestXHTTPVLESSRealityRoundTripPreservesPQV(t *testing.T) {
	q := url.Values{
		"type":     {"xhttp"},
		"security": {"reality"},
		"sni":      {"reality.example"},
		"host":     {"host.example"},
		"path":     {"api?token=1"},
		"mode":     {"stream-one"},
		"flow":     {"xtls-rprx-vision"},
		"alpn":     {"h2,http/1.1"},
		"fp":       {"chrome"},
		"pbk":      {"public-key-value"},
		"sid":      {"shortid-value"},
		"spx":      {"spider-x-value"},
		"pqv":      {"mldsa65-verify-value"},
	}

	v, err := ParseVlessURL(vlessXHTTPTestURL(q))
	if err != nil {
		t.Fatalf("ParseVlessURL() error = %v", err)
	}
	if v.Mldsa65Verify != "mldsa65-verify-value" {
		t.Fatalf("Mldsa65Verify = %q, want mldsa65-verify-value", v.Mldsa65Verify)
	}
	if v.XHTTP == nil {
		t.Fatal("XHTTP config is nil")
	}
	d, property, err := v.Dialer(&dialer.ExtraOption{}, xhttpServerDialer{addr: "127.0.0.1:1"})
	if err == nil {
		if d != nil {
			_ = d
		}
		t.Fatal("V2Ray.Dialer() error = nil, want reality setup failure without live server")
	}
	if property != nil {
		t.Fatalf("property = %+v, want nil when reality setup fails", property)
	}
	if !strings.Contains(err.Error(), "reality") && !strings.Contains(err.Error(), "dial") {
		t.Fatalf("V2Ray.Dialer() error = %v, want reality dial setup failure", err)
	}
	exported := v.ExportToURL()
	parsed, err := url.Parse(exported)
	if err != nil {
		t.Fatalf("url.Parse(exported %q): %v", exported, err)
	}
	for key, want := range map[string]string{
		"security": "reality",
		"sni":      "reality.example",
		"host":     "host.example",
		"path":     "api?token=1",
		"flow":     "xtls-rprx-vision",
		"alpn":     "h2,http/1.1",
		"fp":       "chrome",
		"pbk":      "public-key-value",
		"sid":      "shortid-value",
		"spx":      "spider-x-value",
		"pqv":      "mldsa65-verify-value",
	} {
		if got := parsed.Query().Get(key); got != want {
			t.Fatalf("exported query %s = %q, want %q in %q", key, got, want, exported)
		}
	}
}

func TestXHTTPTransportStreamUpRequestShapes(t *testing.T) {
	recorder := newXHTTPRequestRecorder()
	server := httptest.NewServer(recorder)
	defer server.Close()

	d := newXHTTPTestDialer(t, server.URL, xhttpTestConfig(XHTTPModeStreamUp), "none", "")
	conn, err := d.DialContext(context.Background(), "tcp", "target.example:443")
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	if _, err := conn.Write([]byte("stream-data")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	requests := recorder.waitFor(t, 2)
	var getReq, postReq *xhttpRecordedRequest
	for i := range requests {
		req := requests[i]
		switch req.Method {
		case http.MethodGet:
			getReq = &req
		case http.MethodPost:
			postReq = &req
		}
	}
	if getReq == nil || postReq == nil {
		t.Fatalf("requests = %+v, want one GET and one POST", requests)
	}
	if getReq.Path != postReq.Path {
		t.Fatalf("GET path = %q POST path = %q, want same /api/{uuid}", getReq.Path, postReq.Path)
	}
	if getReq.Host != "xhttp.example" || postReq.Host != "xhttp.example" {
		t.Fatalf("Host values = GET %q POST %q, want xhttp.example", getReq.Host, postReq.Host)
	}
	if !strings.HasPrefix(getReq.Path, "/api/") || strings.Count(strings.TrimPrefix(getReq.Path, "/api/"), "/") != 0 {
		t.Fatalf("stream-up path = %q, want /api/{uuid}", getReq.Path)
	}
	if postReq.ContentType != "application/grpc" {
		t.Fatalf("stream-up POST Content-Type = %q, want application/grpc", postReq.ContentType)
	}
	if postReq.Body != "stream-data" {
		t.Fatalf("stream-up POST body = %q, want stream-data", postReq.Body)
	}
	assertXHTTPRefererPadding(t, getReq.Referer, 100, 1000)
	assertXHTTPRefererPadding(t, postReq.Referer, 100, 1000)
}

func TestXHTTPTransportStreamUpDialReturnsDownstreamSetupError(t *testing.T) {
	getDone := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.Method {
		case http.MethodGet:
			w.WriteHeader(http.StatusBadGateway)
			close(getDone)
		case http.MethodPost:
			<-getDone
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("method = %q, want GET or POST", req.Method)
		}
	}))
	defer server.Close()

	d := newXHTTPTestDialer(t, server.URL, xhttpTestConfig(XHTTPModeStreamUp), "none", "")
	conn, err := d.DialContext(context.Background(), "tcp", "target.example:443")
	if err == nil {
		_ = conn.Close()
		t.Fatal("DialContext() error = nil, want downstream GET status error")
	}
	if !strings.Contains(err.Error(), "xhttp GET") || !strings.Contains(err.Error(), "502 Bad Gateway") {
		t.Fatalf("DialContext() error = %v, want downstream GET 502 status", err)
	}
}

func TestXHTTPTransportPacketUpIgnoresDialContextCancelAfterSetup(t *testing.T) {
	getReady := make(chan struct{})
	allowGetReturn := make(chan struct{})
	postSeen := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, _ = io.Copy(io.Discard, req.Body)
		_ = req.Body.Close()
		switch req.Method {
		case http.MethodGet:
			w.WriteHeader(http.StatusOK)
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
			close(getReady)
			<-allowGetReturn
		case http.MethodPost:
			close(postSeen)
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("method = %q, want GET or POST", req.Method)
		}
	}))
	defer server.Close()
	defer close(allowGetReturn)

	d := newXHTTPTestDialer(t, server.URL, xhttpTestConfig(XHTTPModePacketUp), "none", "")
	ctx, cancel := context.WithCancel(context.Background())
	conn, err := d.DialContext(ctx, "tcp", "target.example:443")
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	defer conn.Close()
	select {
	case <-getReady:
	default:
		t.Fatal("DialContext returned before downstream GET handler marked setup ready")
	}
	cancel()
	if _, err := conn.Write([]byte("still-usable")); err != nil {
		t.Fatalf("Write() after DialContext cancel error = %v", err)
	}
	select {
	case <-postSeen:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for packet-up POST after DialContext cancel")
	}
}

func TestXHTTPTransportStreamUpUploadError(t *testing.T) {
	recorder := newXHTTPRequestRecorder()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		_ = req.Body.Close()
		recorder.mu.Lock()
		recorder.requests = append(recorder.requests, xhttpRecordedRequest{
			Method:      req.Method,
			Path:        req.URL.Path,
			Host:        req.Host,
			ContentType: req.Header.Get("Content-Type"),
			Referer:     req.Header.Get("Referer"),
			Body:        string(body),
		})
		recorder.mu.Unlock()
		select {
		case recorder.seen <- struct{}{}:
		default:
		}
		if req.Method == http.MethodPost {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte{0, 0})
	}))
	defer server.Close()

	d := newXHTTPTestDialer(t, server.URL, xhttpTestConfig(XHTTPModeStreamUp), "none", "")
	conn, err := d.DialContext(context.Background(), "tcp", "target.example:443")
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	if _, err := conn.Write([]byte("rejected")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	err = conn.Close()
	if err == nil || !strings.Contains(err.Error(), "502 Bad Gateway") {
		t.Fatalf("Close() error = %v, want stream POST status", err)
	}

	req := recorder.waitForMethod(t, http.MethodPost)
	if req.Method != http.MethodPost {
		t.Fatalf("method = %q, want POST", req.Method)
	}
	if req.Host != "xhttp.example" {
		t.Fatalf("Host = %q, want xhttp.example", req.Host)
	}
	if !strings.HasPrefix(req.Path, "/api/") || strings.Count(strings.TrimPrefix(req.Path, "/api/"), "/") != 0 {
		t.Fatalf("stream-up path = %q, want /api/{uuid}", req.Path)
	}
	if req.ContentType != "application/grpc" {
		t.Fatalf("POST Content-Type = %q, want application/grpc", req.ContentType)
	}
	if req.Body != "rejected" {
		t.Fatalf("POST body = %q, want rejected", req.Body)
	}
	assertXHTTPRefererPadding(t, req.Referer, 100, 1000)
}

func TestXHTTPTransportStreamOneRequestShape(t *testing.T) {
	recorder := newXHTTPRequestRecorder()
	server := httptest.NewServer(recorder)
	defer server.Close()

	d := newXHTTPTestDialer(t, server.URL, xhttpTestConfig(XHTTPModeStreamOne), "none", "")
	conn, err := d.DialContext(context.Background(), "tcp", "target.example:443")
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	if _, err := conn.Write([]byte("one-data")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	closeStarted := time.Now()
	if err := conn.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if elapsed := time.Since(closeStarted); elapsed > 1500*time.Millisecond {
		t.Fatalf("stream-one Close() took %v, want no upload completion timeout", elapsed)
	}

	requests := recorder.waitFor(t, 1)
	req := requests[0]
	if req.Method != http.MethodPost {
		t.Fatalf("stream-one method = %q, want POST", req.Method)
	}
	if req.Path != "/api/" {
		t.Fatalf("stream-one path = %q, want /api/", req.Path)
	}
	if req.Host != "xhttp.example" {
		t.Fatalf("stream-one Host = %q, want xhttp.example", req.Host)
	}
	if req.RawQuery != "token=1" {
		t.Fatalf("stream-one query = %q, want token=1", req.RawQuery)
	}
	if req.ContentType != "application/grpc" {
		t.Fatalf("stream-one Content-Type = %q, want application/grpc", req.ContentType)
	}
	if req.Body != "one-data" {
		t.Fatalf("stream-one body = %q, want one-data", req.Body)
	}
	assertXHTTPRefererPadding(t, req.Referer, 100, 1000)
}

func TestXHTTPTransportHTTP2ConstructionPath(t *testing.T) {
	recorder := newXHTTPRequestRecorder()
	server := httptest.NewUnstartedServer(recorder)
	if err := http2.ConfigureServer(server.Config, &http2.Server{}); err != nil {
		t.Fatalf("http2.ConfigureServer() error = %v", err)
	}
	server.TLS = server.Config.TLSConfig
	server.StartTLS()
	defer server.Close()

	cfg := xhttpTestConfig(XHTTPModeStreamUp)
	d := newXHTTPTestDialer(t, server.URL, cfg, "tls", "h2")
	conn, err := d.DialContext(context.Background(), "tcp", "target.example:443")
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	if _, err := conn.Write([]byte("h2-data")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	requests := recorder.waitFor(t, 2)
	for _, req := range requests {
		if req.Proto != "HTTP/2.0" {
			t.Fatalf("request proto = %q, want HTTP/2.0 in requests %+v", req.Proto, requests)
		}
	}
}

func TestXHTTPModeAutoDialerResolutionPaths(t *testing.T) {
	tests := []struct {
		name     string
		security string
		alpn     string
		want     string
	}{
		{name: "plain", security: "none", want: XHTTPModePacketUp},
		{name: "tls h2", security: "tls", alpn: "h2", want: XHTTPModeStreamUp},
		{name: "tls h1", security: "tls", alpn: "http/1.1", want: XHTTPModePacketUp},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := url.Values{"type": {"xhttp"}, "security": {tt.security}, "mode": {"auto"}, "path": {"/api"}}
			if tt.alpn != "" {
				q.Set("alpn", tt.alpn)
			}
			v, err := ParseVlessURL(vlessXHTTPTestURL(q))
			if err != nil {
				t.Fatalf("ParseVlessURL() error = %v", err)
			}
			if v.XHTTP.ResolvedMode != tt.want {
				t.Fatalf("ResolvedMode = %q, want %q", v.XHTTP.ResolvedMode, tt.want)
			}
		})
	}
}

func TestXHTTPTransportCloseAndDeadline(t *testing.T) {
	recorder := newXHTTPRequestRecorder()
	server := httptest.NewServer(recorder)
	defer server.Close()
	d := newXHTTPTestDialer(t, server.URL, xhttpTestConfig(XHTTPModePacketUp), "none", "")

	conn, err := d.DialContext(context.Background(), "tcp", "target.example:443")
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	if err := conn.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("SetWriteDeadline() error = %v", err)
	}
	if _, err := conn.Write([]byte("late")); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Write() error = %v, want deadline exceeded", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if _, err := conn.Write([]byte("closed")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Write() after Close error = %v, want net.ErrClosed", err)
	}
}

func TestXHTTPTransportConcurrentCloseAndDeadline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, _ = io.Copy(io.Discard, req.Body)
		_ = req.Body.Close()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte{0, 0})
	}))
	defer server.Close()

	d := newXHTTPTestDialer(t, server.URL, xhttpTestConfig(XHTTPModeStreamUp), "none", "")
	conn, err := d.DialContext(context.Background(), "tcp", "target.example:443")
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			deadline := time.Now().Add(time.Duration(i+1) * time.Millisecond)
			_ = conn.SetReadDeadline(deadline)
			_ = conn.SetWriteDeadline(deadline)
			_ = conn.SetDeadline(deadline)
		}(i)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = conn.Close()
	}()
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("concurrent Close/deadline operations timed out")
	}
}

func assertXHTTPRefererPadding(t *testing.T, referer string, minLen, maxLen int) {
	t.Helper()
	if referer == "" {
		t.Fatal("Referer is empty")
	}
	u, err := url.Parse(referer)
	if err != nil {
		t.Fatalf("url.Parse(Referer %q): %v", referer, err)
	}
	padding := u.Query().Get("x_padding")
	if len(padding) < minLen || len(padding) > maxLen {
		t.Fatalf("x_padding length = %d, want %d..%d in Referer %q", len(padding), minLen, maxLen, referer)
	}
	if strings.Trim(padding, "X") != "" {
		t.Fatalf("x_padding = %q, want repeat X", padding)
	}
}
