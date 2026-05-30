package v2ray

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/daeuniverse/outbound/dialer"
)

const (
	XHTTPModeAuto      = "auto"
	XHTTPModePacketUp  = "packet-up"
	XHTTPModeStreamUp  = "stream-up"
	XHTTPModeStreamOne = "stream-one"

	xhttpDefaultScMaxEachPostBytes = 1000000
)

type XHTTPRange struct {
	From int32
	To   int32
}

func (r XHTTPRange) IsZero() bool {
	return r == XHTTPRange{}
}

type XHTTPConfig struct {
	Mode               string
	ResolvedMode       string
	Host               string
	Path               string
	Query              string
	ScMaxEachPostBytes XHTTPRange
	XPaddingBytes      XHTTPRange
	ExtraRaw           string
}

type xhttpExtraConfig struct {
	Mode                  string
	ScMaxEachPostBytes    XHTTPRange
	ScMaxEachPostBytesSet bool
	XPaddingBytes         XHTTPRange
	XPaddingBytesSet      bool
}

func isXHTTPTransport(network string) bool {
	switch strings.ToLower(network) {
	case "xhttp", "splithttp":
		return true
	default:
		return false
	}
}

func parseVlessXHTTPConfig(q url.Values, data *V2Ray) error {
	if !isXHTTPTransport(data.Net) {
		return nil
	}

	data.Net = strings.ToLower(data.Net)
	if err := rejectUnsupportedXHTTPQuery(q); err != nil {
		return err
	}

	extra, err := parseXHTTPExtra(q.Get("extra"))
	if err != nil {
		return err
	}

	topMode := q.Get("mode")
	if topMode != "" && extra.Mode != "" && topMode != extra.Mode {
		return fmt.Errorf("%w: extra.mode: %v conflicts with mode: %v", dialer.InvalidParameterErr, extra.Mode, topMode)
	}
	mode := topMode
	if mode == "" {
		mode = extra.Mode
	}
	if mode == "" {
		mode = XHTTPModeAuto
	}

	resolvedMode, err := ResolveXHTTPMode(mode, data.TLS, data.Alpn)
	if err != nil {
		return err
	}

	if extra.XPaddingBytesSet && (extra.XPaddingBytes.From <= 0 || extra.XPaddingBytes.To <= 0) {
		return fmt.Errorf("%w: xPaddingBytes cannot be disabled", dialer.InvalidParameterErr)
	}
	if extra.ScMaxEachPostBytesSet && (extra.ScMaxEachPostBytes.From < 0 || extra.ScMaxEachPostBytes.To < 0) {
		return fmt.Errorf("%w: scMaxEachPostBytes: %v-%v", dialer.InvalidParameterErr, extra.ScMaxEachPostBytes.From, extra.ScMaxEachPostBytes.To)
	}

	serverName := data.SNI
	if serverName == "" {
		serverName = q.Get("serverName")
		data.SNI = serverName
	}

	normalizedPath, rawQuery := NormalizeXHTTPPath(data.Path)
	config := &XHTTPConfig{
		Mode:               mode,
		ResolvedMode:       resolvedMode,
		Path:               normalizedPath,
		Query:              rawQuery,
		ScMaxEachPostBytes: extra.ScMaxEachPostBytes,
		XPaddingBytes:      extra.XPaddingBytes,
		ExtraRaw:           q.Get("extra"),
	}
	if config.ScMaxEachPostBytes.IsZero() {
		config.ScMaxEachPostBytes = XHTTPRange{From: xhttpDefaultScMaxEachPostBytes, To: xhttpDefaultScMaxEachPostBytes}
	}
	if data.TLS == "reality" {
		config.Host = ResolveXHTTPHost(data.Host, "", serverName, data.Add)
	} else {
		config.Host = ResolveXHTTPHost(data.Host, serverName, "", data.Add)
	}

	data.XHTTP = config
	return nil
}

func rejectUnsupportedXHTTPQuery(q url.Values) error {
	unsupported := map[string]struct{}{
		"browserdialer":         {},
		"cmaxreusetimes":        {},
		"downloadsettings":      {},
		"hkeepaliveperiod":      {},
		"hmaxrequesttimes":      {},
		"headers":               {},
		"headers.host":          {},
		"maxconcurrency":        {},
		"maxconnections":        {},
		"nogrpcheader":          {},
		"nosseheader":           {},
		"scmaxbufferedposts":    {},
		"scmaxeachpostbytes":    {},
		"scminpostsintervalms":  {},
		"scstreamupserversecs":  {},
		"seqkey":                {},
		"seqplacement":          {},
		"servermaxheaderbytes":  {},
		"sessionkey":            {},
		"sessionplacement":      {},
		"uplinkchunksize":       {},
		"uplinkdatakey":         {},
		"uplinkdataplacement":   {},
		"uplinkhttpmethod":      {},
		"xmux":                  {},
		"xmux.cmaxreusetimes":   {},
		"xmux.hkeepaliveperiod": {},
		"xmux.hmaxrequesttimes": {},
		"xmux.hmaxreusablesecs": {},
		"xmux.maxconcurrency":   {},
		"xmux.maxconnections":   {},
		"xpaddingbytes":         {},
		"xpaddingheader":        {},
		"xpaddingkey":           {},
		"xpaddingmethod":        {},
		"xpaddingobfsmode":      {},
		"xpaddingplacement":     {},
	}

	keys := make([]string, 0, len(q))
	for key := range q {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if _, ok := unsupported[strings.ToLower(key)]; ok {
			return fmt.Errorf("%w: %s: %v", dialer.UnexpectedFieldErr, key, q.Get(key))
		}
	}
	return validateXHTTPALPN(q.Get("alpn"))
}

func parseXHTTPExtra(raw string) (xhttpExtraConfig, error) {
	if raw == "" {
		return xhttpExtraConfig{}, nil
	}

	fields := make(map[string]json.RawMessage)
	if err := json.Unmarshal([]byte(raw), &fields); err != nil {
		return xhttpExtraConfig{}, fmt.Errorf("%w: extra: %v", dialer.InvalidParameterErr, err)
	}

	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var extra xhttpExtraConfig
	for _, key := range keys {
		rawValue := fields[key]
		switch key {
		case "mode":
			if err := json.Unmarshal(rawValue, &extra.Mode); err != nil {
				return xhttpExtraConfig{}, fmt.Errorf("%w: extra.mode: %v", dialer.InvalidParameterErr, err)
			}
			if extra.Mode != "" {
				if err := validateXHTTPMode(extra.Mode); err != nil {
					return xhttpExtraConfig{}, fmt.Errorf("%w: extra.mode: %v", err, extra.Mode)
				}
			}
		case "scMaxEachPostBytes":
			r, err := parseXHTTPRange(rawValue, "extra.scMaxEachPostBytes")
			if err != nil {
				return xhttpExtraConfig{}, err
			}
			extra.ScMaxEachPostBytes = r
			extra.ScMaxEachPostBytesSet = true
		case "xPaddingBytes":
			r, err := parseXHTTPRange(rawValue, "extra.xPaddingBytes")
			if err != nil {
				return xhttpExtraConfig{}, err
			}
			extra.XPaddingBytes = r
			extra.XPaddingBytesSet = true
		default:
			return xhttpExtraConfig{}, fmt.Errorf("%w: extra.%s: %s", dialer.UnexpectedFieldErr, key, string(rawValue))
		}
	}
	return extra, nil
}

func parseXHTTPRange(raw json.RawMessage, field string) (XHTTPRange, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return parseXHTTPRangeString(s, field)
	}

	var i int32
	if err := json.Unmarshal(raw, &i); err == nil {
		return orderedXHTTPRange(i, i), nil
	}

	return XHTTPRange{}, fmt.Errorf("%w: %s: expected integer or range string", dialer.InvalidParameterErr, field)
}

func parseXHTTPRangeString(s, field string) (XHTTPRange, error) {
	if v, err := strconv.ParseInt(s, 10, 32); err == nil {
		return orderedXHTTPRange(int32(v), int32(v)), nil
	}
	if s == "" {
		return XHTTPRange{}, nil
	}

	var pair []string
	if strings.HasPrefix(s, "-") {
		parts := strings.SplitN(s, "-", 3)
		if len(parts) == 3 {
			pair = []string{parts[0] + "-" + parts[1], parts[2]}
		}
	} else {
		pair = strings.SplitN(s, "-", 2)
	}
	if len(pair) == 2 {
		left, leftErr := strconv.ParseInt(pair[0], 10, 32)
		right, rightErr := strconv.ParseInt(pair[1], 10, 32)
		if leftErr == nil && rightErr == nil {
			return orderedXHTTPRange(int32(left), int32(right)), nil
		}
	}

	return XHTTPRange{}, fmt.Errorf("%w: %s: %s", dialer.InvalidParameterErr, field, s)
}

func orderedXHTTPRange(left, right int32) XHTTPRange {
	if left > right {
		left, right = right, left
	}
	return XHTTPRange{From: left, To: right}
}

func validateXHTTPMode(mode string) error {
	switch mode {
	case XHTTPModeAuto, XHTTPModePacketUp, XHTTPModeStreamUp, XHTTPModeStreamOne:
		return nil
	default:
		return fmt.Errorf("%w: xhttp mode: %v", dialer.InvalidParameterErr, mode)
	}
}

func validateXHTTPALPN(alpn string) error {
	for _, protocol := range splitXHTTPALPN(alpn) {
		switch protocol {
		case "h3", "quic":
			return fmt.Errorf("%w: alpn: %v", dialer.UnexpectedFieldErr, protocol)
		}
	}
	return nil
}

func splitXHTTPALPN(alpn string) []string {
	if alpn == "" {
		return nil
	}
	parts := strings.Split(alpn, ",")
	protocols := make([]string, 0, len(parts))
	for _, part := range parts {
		protocol := strings.ToLower(strings.TrimSpace(part))
		if protocol != "" {
			protocols = append(protocols, protocol)
		}
	}
	return protocols
}

func ResolveXHTTPMode(mode, security, alpn string) (string, error) {
	if mode == "" {
		mode = XHTTPModeAuto
	}
	if err := validateXHTTPMode(mode); err != nil {
		return "", err
	}
	if err := validateXHTTPALPN(alpn); err != nil {
		return "", err
	}
	if mode != XHTTPModeAuto {
		return mode, nil
	}
	return ResolveXHTTPAutoMode(security, alpn)
}

func ResolveXHTTPAutoMode(security, alpn string) (string, error) {
	if err := validateXHTTPALPN(alpn); err != nil {
		return "", err
	}
	switch strings.ToLower(security) {
	case "reality":
		return XHTTPModeStreamOne, nil
	case "tls":
		protocols := splitXHTTPALPN(alpn)
		if len(protocols) == 1 && protocols[0] == "http/1.1" {
			return XHTTPModePacketUp, nil
		}
		return XHTTPModeStreamUp, nil
	default:
		return XHTTPModePacketUp, nil
	}
}

func NormalizeXHTTPPath(path string) (normalizedPath, rawQuery string) {
	path, rawQuery, _ = strings.Cut(path, "?")
	if path == "" || path[0] != '/' {
		path = "/" + path
	}
	if path[len(path)-1] != '/' {
		path += "/"
	}
	return path, rawQuery
}

func ResolveXHTTPHost(explicitHost, tlsServerName, realityServerName, address string) string {
	for _, host := range []string{explicitHost, tlsServerName, realityServerName, address} {
		if strings.TrimSpace(host) != "" {
			return strings.TrimSpace(host)
		}
	}
	return ""
}
