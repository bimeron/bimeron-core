package accesskey

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"gopkg.in/yaml.v3"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"bimeron/internal/problem"
)

const maxBytes = 64 * 1024

// Endpoint holds secrets and must never be included in logs.
type Endpoint struct {
	Host   string
	Port   int
	Cipher string
	Secret string
	Prefix string
}
type Profile struct {
	Name           string
	TCP            Endpoint
	UDP            Endpoint
	Type           string // Empty means Shadowsocks for existing API callers.
	Username       string // SOCKS5 and HTTP CONNECT; Secret contains the password.
	VLESS          VLESS
	Trojan         Trojan
	Naive          Naive
	VMess          VMess
	Hysteria2      Hysteria2
	AnyTLS         AnyTLS
	SSH            SSH
	TUIC           TUIC
	MASQUE         MASQUE
	SSPlugin       *SSPlugin
	HTTPServerName string // Nonempty enables verified TLS for HTTP CONNECT.
	ShadowTLS      *ShadowTLS
}

// AnyTLS contains password authentication and verified TLS settings.
type AnyTLS struct{ Password, ServerName string }

func (a AnyTLS) Validate(host string, port int) error {
	if err := endpointProblem("invalid AnyTLS server endpoint", host, port); err != nil {
		return err
	}
	if err := passwordProblem("invalid AnyTLS password", a.Password); err != nil {
		return err
	}
	return serverNameProblem("invalid AnyTLS server name", a.ServerName)
}

// ParseAnyTLS never includes credentials or the input URI in errors.
func ParseAnyTLS(raw string) (Profile, error) {
	const invalidURI = "invalid AnyTLS URI"
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "anytls" || u.Opaque != "" || (u.Path != "" && u.Path != "/") {
		return Profile{}, problem.New("uri_invalid", invalidURI)
	}
	if u.Hostname() == "" {
		return Profile{}, problem.New("value_required", invalidURI).On("Server", "")
	}
	if u.User == nil {
		return Profile{}, problem.New("value_required", invalidURI).On("Password", "")
	}
	if _, ok := u.User.Password(); ok {
		return Profile{}, problem.New("uri_credentials_invalid", "invalid AnyTLS password").On("Password", u.User.String())
	}
	port := 443
	if u.Port() != "" {
		port, err = strconv.Atoi(u.Port())
		if err != nil {
			return Profile{}, problem.New("port_invalid", "invalid AnyTLS port").At("Port")
		}
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return Profile{}, problem.New("uri_invalid", "invalid AnyTLS options")
	}
	for key, values := range q {
		const message = "unsupported or duplicate AnyTLS option"
		if (key != "sni" && key != "insecure") || len(values) != 1 {
			return Profile{}, problem.New("uri_option_unsupported", message)
		}
		if key == "insecure" && values[0] != "0" {
			return Profile{}, problem.New("insecure_tls_unsupported", message).At("Insecure")
		}
	}
	a := AnyTLS{Password: u.User.Username(), ServerName: q.Get("sni")}
	if !q.Has("sni") {
		a.ServerName = u.Hostname()
	}
	if err := a.Validate(u.Hostname(), port); err != nil {
		return Profile{}, err
	}
	e := Endpoint{Host: u.Hostname(), Port: port}
	return Profile{Type: "anytls", Name: u.Fragment, TCP: e, UDP: e, AnyTLS: a}, nil
}

// SSH describes a TCP-only SSH upstream. Paths never contain key material.
type SSH struct {
	User, IdentityFile, KnownHostsFile string
}

func ParseSSH(raw string) (Profile, error) {
	const invalidURI = "invalid SSH URI"
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "ssh" || u.Opaque != "" || u.Path != "" {
		return Profile{}, problem.New("uri_invalid", invalidURI)
	}
	if u.Hostname() == "" {
		return Profile{}, problem.New("value_required", invalidURI).On("Server", "")
	}
	if u.User == nil || u.User.Username() == "" {
		return Profile{}, problem.New("value_required", invalidURI).On("Username", "")
	}
	if password, ok := u.User.Password(); ok {
		return Profile{}, problem.New("option_not_supported", "SSH URI passwords are not supported").On("Password", password).Arg("type", "SSH")
	}
	port := 22
	if u.Port() != "" {
		port, err = strconv.Atoi(u.Port())
		if err != nil {
			return Profile{}, problem.New("port_invalid", "invalid SSH port").At("Port")
		}
	}
	if port < 1 || port > 65535 {
		return Profile{}, problem.New("port_invalid", "invalid SSH port").At("Port")
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return Profile{}, problem.New("uri_invalid", "invalid SSH options")
	}
	for key, values := range q {
		const message = "unsupported or duplicate SSH option"
		if (key != "identity" && key != "known_hosts") || len(values) != 1 {
			return Profile{}, problem.New("uri_option_unsupported", message)
		}
		if values[0] == "" {
			field := "IdentityFile"
			if key == "known_hosts" {
				field = "KnownHostsFile"
			}
			return Profile{}, problem.New("value_required", message).On(field, "")
		}
	}
	return Profile{Type: "ssh", Name: u.Fragment, TCP: Endpoint{Host: u.Hostname(), Port: port}, SSH: SSH{User: u.User.Username(), IdentityFile: q.Get("identity"), KnownHostsFile: q.Get("known_hosts")}}, nil
}

// Hysteria2 contains the authentication and verified TLS settings.
type Hysteria2 struct{ Password, ServerName, ALPN, Fingerprint string }

func (h Hysteria2) Validate(host string, port int) error {
	if err := endpointProblem("invalid Hysteria2 server endpoint", host, port); err != nil {
		return err
	}
	if err := passwordProblem("invalid Hysteria2 password", h.Password); err != nil {
		return err
	}
	if err := serverNameProblem("invalid Hysteria2 server name", h.ServerName); err != nil {
		return err
	}
	if h.ALPN != "" && h.ALPN != "h3" {
		return problem.New("alpn_invalid", "unsupported Hysteria2 ALPN").At("ALPN").Arg("allowed", "h3")
	}
	switch h.Fingerprint {
	case "", "firefox", "firefox-116", "firefox-116b", "firefox-116c", "chrome", "chrome-115", "chrome-146":
	default:
		return hysteria2FingerprintProblem()
	}
	return nil
}

func hysteria2FingerprintProblem() error {
	return problem.New("fingerprint_unsupported", "unsupported Hysteria2 QUIC fingerprint").At("Fingerprint").Arg("allowed", "firefox, firefox-116, firefox-116b, firefox-116c, chrome, chrome-115, chrome-146")
}

// ParseHysteria2 never includes credentials or the input URI in errors.
func ParseHysteria2(raw string) (Profile, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "hysteria2" && u.Scheme != "hy2") || u.Path != "" || u.Opaque != "" {
		return Profile{}, problem.New("uri_invalid", "invalid Hysteria2 URI")
	}
	if u.Hostname() == "" {
		return Profile{}, problem.New("value_required", "invalid Hysteria2 URI").On("Server", "")
	}
	if u.User != nil {
		if _, ok := u.User.Password(); ok {
			return Profile{}, problem.New("uri_credentials_invalid", "invalid Hysteria2 password").On("Password", u.User.String())
		}
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return Profile{}, problem.New("port_invalid", "invalid Hysteria2 port").At("Port")
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return Profile{}, problem.New("uri_invalid", "invalid Hysteria2 options")
	}
	for key, values := range q {
		if (key != "sni" && key != "auth" && key != "insecure" && key != "alpn" && key != "fp") || len(values) != 1 {
			return Profile{}, problem.New("uri_option_unsupported", "unsupported or duplicate Hysteria2 option")
		}
	}
	if q.Has("auth") && u.User != nil {
		return Profile{}, problem.New("uri_option_unsupported", "duplicate Hysteria2 password source").On("Password", q.Get("auth")+u.User.Username())
	}
	if q.Has("insecure") && q.Get("insecure") != "0" {
		return Profile{}, problem.New("insecure_tls_unsupported", "unsupported Hysteria2 insecure TLS option").At("Insecure")
	}
	if q.Has("fp") && q.Get("fp") == "" {
		return Profile{}, hysteria2FingerprintProblem()
	}
	h := Hysteria2{Password: q.Get("auth"), ServerName: q.Get("sni"), ALPN: q.Get("alpn"), Fingerprint: q.Get("fp")}
	if u.User != nil {
		h.Password = u.User.Username()
	}
	if !q.Has("sni") {
		h.ServerName = u.Hostname()
	}
	if err := h.Validate(u.Hostname(), port); err != nil {
		return Profile{}, err
	}
	e := Endpoint{Host: u.Hostname(), Port: port}
	return Profile{Type: "hysteria2", Name: u.Fragment, TCP: e, UDP: e, Hysteria2: h}, nil
}

// Trojan holds authentication and verified TLS transport settings.
type Trojan struct {
	Password, ServerName           string
	Network, ALPN, WSPath, WSHost  string
	GRPCServiceName, GRPCAuthority string
	GRPCMultiMode                  bool
}

func (t Trojan) Validate(host string, port int) error {
	if err := endpointProblem("invalid Trojan server endpoint", host, port); err != nil {
		return err
	}
	if err := passwordProblem("invalid Trojan password", t.Password); err != nil {
		return err
	}
	if err := serverNameProblem("invalid Trojan server name", t.ServerName); err != nil {
		return err
	}
	network := t.Network
	if network == "" {
		network = "tcp"
	}
	if network != "tcp" && network != "ws" && network != "grpc" {
		return problem.New("choice_invalid", "unsupported Trojan transport").At("Network").Arg("allowed", "tcp, ws, grpc")
	}
	if network != "ws" && (t.WSPath != "" || t.WSHost != "") {
		return requiresTransport("Trojan WebSocket options require type=ws", "WebSocket", firstSet([]string{"WSPath", "WSHost"}, t.WSPath != "", t.WSHost != ""))
	}
	if network == "ws" {
		if err := wsPathProblem("invalid or unsupported Trojan WebSocket path", t.WSPath); err != nil {
			return err
		}
		if t.WSHost != "" {
			h, err := url.Parse("https://" + t.WSHost)
			if err != nil || h.Hostname() == "" || h.User != nil || h.Path != "" || h.RawQuery != "" || h.Fragment != "" || strings.ContainsAny(t.WSHost, " \t\r\n") {
				return problem.New("host_invalid", "invalid Trojan WebSocket host").At("WSHost")
			}
		}
	}
	if network != "grpc" && (t.GRPCServiceName != "" || t.GRPCAuthority != "" || t.GRPCMultiMode) {
		return requiresTransport("Trojan gRPC options require type=grpc", "gRPC", firstSet([]string{"GRPCServiceName", "GRPCAuthority", "GRPCMultiMode"}, t.GRPCServiceName != "", t.GRPCAuthority != "", t.GRPCMultiMode))
	}
	if network == "grpc" && t.GRPCServiceName == "" {
		return problem.New("value_required", "invalid Trojan gRPC service name").On("GRPCServiceName", "")
	}
	if network == "grpc" && strings.ContainsAny(t.GRPCServiceName, "/?\\#| \t\r\n") {
		return problem.New("value_has_invalid_characters", "invalid Trojan gRPC service name").At("GRPCServiceName")
	}
	if t.GRPCAuthority != "" && (strings.ContainsAny(t.GRPCAuthority, " /\\@?#\t\r\n") || strings.HasPrefix(t.GRPCAuthority, ":")) {
		return problem.New("host_invalid", "invalid Trojan gRPC authority").At("GRPCAuthority")
	}
	if t.ALPN != "" {
		for _, protocol := range strings.Split(t.ALPN, ",") {
			if protocol == "" || strings.ContainsAny(protocol, " \t\r\n") || (network == "ws" && protocol != "http/1.1") || (network == "grpc" && protocol != "h2") {
				return alpnProblem("invalid Trojan ALPN", network)
			}
		}
	}
	return nil
}

// ParseTrojan never includes credentials or the input URI in errors.
func ParseTrojan(raw string) (Profile, error) {
	const invalidURI = "invalid Trojan URI"
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "trojan" || u.Path != "" {
		return Profile{}, problem.New("uri_invalid", invalidURI)
	}
	if u.Hostname() == "" {
		return Profile{}, problem.New("value_required", invalidURI).On("Server", "")
	}
	if u.User == nil {
		return Profile{}, problem.New("value_required", invalidURI).On("Password", "")
	}
	if _, ok := u.User.Password(); ok {
		return Profile{}, problem.New("uri_credentials_invalid", "invalid Trojan password").On("Password", u.User.String())
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return Profile{}, problem.New("port_invalid", "invalid Trojan port").At("Port")
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return Profile{}, problem.New("uri_invalid", "invalid Trojan options")
	}
	for key, values := range q {
		if (key != "sni" && key != "type" && key != "security" && key != "alpn" && key != "path" && key != "host" && key != "serviceName" && key != "authority" && key != "mode") || len(values) != 1 {
			return Profile{}, problem.New("uri_option_unsupported", "unsupported or duplicate Trojan option")
		}
	}
	if q.Has("type") && q.Get("type") == "" {
		return Profile{}, problem.New("choice_invalid", "unsupported Trojan transport or security").At("Network").Arg("allowed", "tcp, ws, grpc")
	}
	if q.Has("security") && q.Get("security") != "tls" {
		return Profile{}, problem.New("choice_invalid", "unsupported Trojan transport or security").At("Security").Arg("allowed", "tls")
	}
	t := Trojan{Password: u.User.Username(), ServerName: q.Get("sni"), Network: q.Get("type"), ALPN: q.Get("alpn"), WSPath: q.Get("path"), WSHost: q.Get("host"), GRPCServiceName: q.Get("serviceName"), GRPCAuthority: q.Get("authority"), GRPCMultiMode: q.Get("mode") == "multi"}
	if t.Network == "" {
		t.Network = "tcp"
	}
	const transportOptions = "unsupported Trojan transport options"
	if (q.Has("path") || q.Has("host")) && t.Network != "ws" {
		return Profile{}, requiresTransport(transportOptions, "WebSocket", firstSet([]string{"WSPath", "WSHost"}, q.Has("path"), q.Has("host")))
	}
	if (q.Has("serviceName") || q.Has("authority") || q.Has("mode")) && t.Network != "grpc" {
		return Profile{}, requiresTransport(transportOptions, "gRPC", firstSet([]string{"GRPCServiceName", "GRPCAuthority", "GRPCMultiMode"}, q.Has("serviceName"), q.Has("authority"), q.Has("mode")))
	}
	if q.Has("mode") && q.Get("mode") != "gun" && q.Get("mode") != "multi" {
		return Profile{}, problem.New("choice_invalid", transportOptions).At("GRPCMultiMode").Arg("allowed", "gun, multi")
	}
	if t.ServerName == "" && !q.Has("sni") {
		t.ServerName = u.Hostname()
	}
	if err := t.Validate(u.Hostname(), port); err != nil {
		return Profile{}, err
	}
	e := Endpoint{Host: u.Hostname(), Port: port}
	return Profile{Type: "trojan", Name: u.Fragment, TCP: e, UDP: e, Trojan: t}, nil
}

// VLESS contains the supported VLESS security and transport settings.
type VLESS struct {
	ID, Flow, Network, Security, Encryption              string
	ServerName, PublicKey, ShortID, Fingerprint, SpiderX string
	ALPN, WSPath, WSHost                                 string
	WSEarlyData                                          int
	GRPCServiceName                                      string
	GRPCAuthority                                        string
	GRPCMultiMode                                        bool
	XHTTPPath, XHTTPHost, XHTTPMode                      string
	XHTTPOptions                                         *XHTTPOptions
}

var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func (v VLESS) Validate(host string, port int) error {
	if err := endpointProblem("invalid VLESS server endpoint", host, port); err != nil {
		return err
	}
	if !uuidPattern.MatchString(v.ID) {
		return problem.New("uuid_invalid", "invalid VLESS user ID").On("ID", v.ID)
	}
	if v.Encryption != "none" {
		return problem.New("choice_invalid", "unsupported VLESS transport, security, encryption or flow").On("Encryption", v.Encryption).Arg("allowed", "none")
	}
	vision := v.Flow == "xtls-rprx-vision" || v.Flow == "xtls-rprx-vision-udp443"
	if !((v.Network == "tcp" && v.Security == "reality" && (vision || v.Flow == "")) || (v.Network == "tcp" && v.Security == "tls" && v.Flow == "") || (v.Network == "ws" && v.Security == "tls" && v.Flow == "") || (v.Network == "grpc" && (v.Security == "tls" || v.Security == "reality") && v.Flow == "") || (v.Network == "xhttp" && v.Security == "tls" && v.Flow == "" && (v.XHTTPMode == "packet-up" || v.XHTTPMode == "stream-up" || v.XHTTPMode == "stream-one" || v.XHTTPMode == "auto")) || (v.Network == "xhttp" && v.Security == "reality" && v.Flow == "" && (v.XHTTPMode == "stream-one" || v.XHTTPMode == "stream-up" || v.XHTTPMode == "auto"))) {
		return v.matrixProblem("unsupported VLESS transport, security or flow", vision)
	}
	if strings.ContainsAny(v.ServerName, " /\t\r\n") {
		return problem.New("server_name_invalid", "invalid VLESS server name").At("ServerName")
	}
	if v.Fingerprint != "" {
		switch v.Fingerprint {
		case "chrome", "firefox", "safari", "ios", "android", "edge":
		default:
			return problem.New("fingerprint_unsupported", "unsupported VLESS fingerprint").At("Fingerprint").Arg("allowed", "chrome, firefox, safari, ios, android, edge")
		}
	}
	if v.Security == "reality" {
		const message = "invalid VLESS REALITY settings"
		switch {
		case v.ServerName == "":
			return problem.New("value_required", message).On("ServerName", "").Also("Security")
		case v.Fingerprint == "":
			return problem.New("value_required", message).On("Fingerprint", "").Also("Security")
		case v.WSPath != "" || v.WSHost != "":
			return requiresTransport(message, "WebSocket", firstSet([]string{"WSPath", "WSHost"}, v.WSPath != "", v.WSHost != ""))
		case v.Network == "tcp" && v.ALPN != "":
			return problem.New("combination_unsupported", message).At("ALPN").Also("Security", "Network")
		case (v.Network == "xhttp" || v.Network == "grpc") && v.ALPN != "" && v.ALPN != "h2":
			return problem.New("alpn_invalid", message).At("ALPN").Also("Security").Arg("allowed", "h2")
		}
		key, err := base64.RawURLEncoding.DecodeString(v.PublicKey)
		if err != nil || len(key) != 32 {
			return problem.New("reality_public_key_invalid", "invalid VLESS REALITY public key").On("PublicKey", v.PublicKey)
		}
		if len(v.ShortID) > 16 || len(v.ShortID)%2 != 0 {
			return problem.New("reality_short_id_invalid", "invalid VLESS REALITY short ID").At("ShortID")
		}
		if _, err := hex.DecodeString(v.ShortID); err != nil {
			return problem.New("reality_short_id_invalid", "invalid VLESS REALITY short ID").At("ShortID")
		}
	} else if v.PublicKey != "" || v.ShortID != "" || v.SpiderX != "" {
		field := firstSet([]string{"PublicKey", "ShortID", "SpiderX"}, v.PublicKey != "", v.ShortID != "", v.SpiderX != "")
		return problem.New("option_requires_security", "REALITY options require security=reality").At(field).Also("Security").Arg("security", "REALITY")
	}
	if v.Network != "ws" && (v.WSPath != "" || v.WSHost != "") {
		return requiresTransport("WebSocket options require type=ws", "WebSocket", firstSet([]string{"WSPath", "WSHost"}, v.WSPath != "", v.WSHost != ""))
	}
	if v.Network == "ws" {
		if err := wsPathProblem("invalid or unsupported VLESS WebSocket path", v.WSPath); err != nil {
			return err
		}
		if v.WSHost != "" {
			host, err := url.Parse("https://" + v.WSHost)
			if err != nil || host.Hostname() == "" || host.User != nil || host.Path != "" || host.RawQuery != "" || host.Fragment != "" {
				return problem.New("host_invalid", "invalid VLESS WebSocket host").At("WSHost")
			}
		}
	}
	if v.WSEarlyData < 0 || v.WSEarlyData > 8192 {
		return problem.New("number_out_of_range", "invalid VLESS WebSocket early data").At("WSEarlyData").Arg("min", "0").Arg("max", "8192")
	}
	if v.Network != "ws" && v.WSEarlyData != 0 {
		return requiresTransport("invalid VLESS WebSocket early data", "WebSocket", "WSEarlyData")
	}
	if v.Network != "grpc" && (v.GRPCServiceName != "" || v.GRPCAuthority != "" || v.GRPCMultiMode) {
		return requiresTransport("gRPC options require type=grpc", "gRPC", firstSet([]string{"GRPCServiceName", "GRPCAuthority", "GRPCMultiMode"}, v.GRPCServiceName != "", v.GRPCAuthority != "", v.GRPCMultiMode))
	}
	if v.Network == "grpc" {
		const message = "invalid VLESS gRPC service name"
		switch {
		case v.GRPCServiceName == "":
			return problem.New("value_required", message).On("GRPCServiceName", "")
		case strings.ContainsAny(v.GRPCServiceName, "?\\# \t\r\n"):
			return problem.New("value_has_invalid_characters", message).At("GRPCServiceName")
		case strings.Contains(v.GRPCServiceName, "/") && (!strings.HasPrefix(v.GRPCServiceName, "/") || strings.HasSuffix(v.GRPCServiceName, "/") || strings.Contains(v.GRPCServiceName, "//")):
			return problem.New("grpc_service_name_invalid", message).At("GRPCServiceName")
		}
	}
	if v.GRPCAuthority != "" && (strings.ContainsAny(v.GRPCAuthority, " /\\@?#\t\r\n") || strings.HasPrefix(v.GRPCAuthority, ":")) {
		return problem.New("host_invalid", "invalid VLESS gRPC authority").At("GRPCAuthority")
	}
	if v.Network != "xhttp" && (v.XHTTPPath != "" || v.XHTTPHost != "" || v.XHTTPMode != "" || v.XHTTPOptions != nil) {
		return requiresTransport("XHTTP options require type=xhttp", "XHTTP", firstSet([]string{"XHTTPPath", "XHTTPHost", "XHTTPMode", "XHTTPExtra"}, v.XHTTPPath != "", v.XHTTPHost != "", v.XHTTPMode != "", v.XHTTPOptions != nil))
	}
	if v.Network == "xhttp" {
		if err := v.XHTTPOptions.Validate(v.XHTTPMode, v.Security, v.ALPN); err != nil {
			return err
		}
		if v.ALPN == "h3" && v.Security != "tls" {
			return problem.New("option_requires_security", "HTTP/3 requires TLS without a TLS fingerprint").At("ALPN").Also("Security").Arg("security", "TLS")
		}
		if v.ALPN == "h3" && v.Fingerprint != "" {
			return problem.New("http3_fingerprint_unsupported", "HTTP/3 requires TLS without a TLS fingerprint").At("Fingerprint").Also("ALPN")
		}
		if v.XHTTPPath != "" {
			path, err := url.ParseRequestURI(v.XHTTPPath)
			if err != nil || path.IsAbs() || !strings.HasPrefix(v.XHTTPPath, "/") || strings.ContainsAny(v.XHTTPPath, "#\\\r\n") {
				return problem.New("path_invalid", "invalid VLESS XHTTP path").At("XHTTPPath")
			}
		}
		if v.XHTTPHost != "" {
			host, err := url.Parse("https://" + v.XHTTPHost)
			if err != nil || host.Hostname() == "" || host.User != nil || host.Path != "" || host.RawQuery != "" || host.Fragment != "" || strings.ContainsAny(v.XHTTPHost, " \t\r\n") {
				return problem.New("host_invalid", "invalid VLESS XHTTP host").At("XHTTPHost")
			}
		}
	}
	if v.ALPN != "" {
		for _, protocol := range strings.Split(v.ALPN, ",") {
			if protocol == "" || strings.ContainsAny(protocol, " \t\r\n") || (v.Network == "ws" && protocol != "http/1.1") || (v.Network == "grpc" && protocol != "h2") || (v.Network == "xhttp" && protocol != "h2" && protocol != "h3" && protocol != "http/1.1") || (v.Network == "xhttp" && strings.Contains(v.ALPN, ",") && v.ALPN != "h2,http/1.1") {
				return alpnProblem("invalid VLESS ALPN", v.Network)
			}
		}
	}
	return nil
}

// matrixProblem names the field that breaks the VLESS transport, security and
// flow matrix. Single-field checks run first; the rest is a combination rule.
func (v VLESS) matrixProblem(message string, vision bool) error {
	switch {
	case v.Network != "tcp" && v.Network != "ws" && v.Network != "grpc" && v.Network != "xhttp":
		return problem.New("choice_invalid", message).On("Network", v.Network).Arg("allowed", "tcp, ws, grpc, xhttp")
	case v.Security != "tls" && v.Security != "reality":
		return problem.New("choice_invalid", message).On("Security", v.Security).Arg("allowed", "tls, reality")
	case v.Flow != "" && !vision:
		return problem.New("choice_invalid", message).At("Flow").Arg("allowed", "xtls-rprx-vision, xtls-rprx-vision-udp443")
	case v.Network == "xhttp" && v.XHTTPMode != "packet-up" && v.XHTTPMode != "stream-up" && v.XHTTPMode != "stream-one" && v.XHTTPMode != "auto":
		return problem.New("choice_invalid", message).On("XHTTPMode", v.XHTTPMode).Arg("allowed", "packet-up, stream-up, stream-one, auto")
	case v.Flow != "":
		return problem.New("combination_unsupported", message).At("Flow").Also("Network", "Security")
	case v.Network == "xhttp":
		return problem.New("combination_unsupported", message).At("XHTTPMode").Also("Network", "Security")
	}
	return problem.New("combination_unsupported", message).At("Security").Also("Network")
}

// ParseVLESS never includes the input URI or credentials in errors.
func ParseVLESS(raw string) (Profile, error) {
	const invalidURI = "invalid VLESS URI"
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "vless" || u.Path != "" {
		return Profile{}, problem.New("uri_invalid", invalidURI)
	}
	if u.Hostname() == "" {
		return Profile{}, problem.New("value_required", invalidURI).On("Server", "")
	}
	if u.User == nil {
		return Profile{}, problem.New("value_required", invalidURI).On("ID", "")
	}
	if _, ok := u.User.Password(); ok {
		return Profile{}, problem.New("uri_credentials_invalid", "invalid VLESS user ID").On("ID", u.User.String())
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return Profile{}, problem.New("port_invalid", "invalid VLESS port").At("Port")
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return Profile{}, problem.New("uri_invalid", "invalid VLESS options")
	}
	allowed := map[string]bool{"encryption": true, "flow": true, "type": true, "security": true, "sni": true, "pbk": true, "sid": true, "fp": true, "spx": true, "alpn": true, "path": true, "host": true, "ed": true, "serviceName": true, "authority": true, "mode": true, "extra": true}
	for k, values := range q {
		if !allowed[k] || len(values) != 1 {
			return Profile{}, problem.New("uri_option_unsupported", "unsupported or duplicate VLESS option")
		}
	}
	if err := vlessTransportOptionsProblem(q); err != nil {
		return Profile{}, err
	}
	v := VLESS{ID: u.User.Username(), Flow: q.Get("flow"), Network: q.Get("type"), Security: q.Get("security"), Encryption: q.Get("encryption"), ServerName: q.Get("sni"), PublicKey: q.Get("pbk"), ShortID: q.Get("sid"), Fingerprint: q.Get("fp"), SpiderX: q.Get("spx"), ALPN: q.Get("alpn"), WSPath: q.Get("path"), WSHost: q.Get("host")}
	if v.Network == "ws" && v.WSPath != "" {
		path, pathErr := url.ParseRequestURI(v.WSPath)
		if pathErr != nil {
			return Profile{}, problem.New("path_invalid", "invalid VLESS WebSocket path").At("WSPath")
		}
		pathQuery := path.Query()
		if values, ok := pathQuery["ed"]; ok {
			if q.Has("ed") || len(values) != 1 {
				return Profile{}, problem.New("uri_option_unsupported", "duplicate VLESS WebSocket early data").At("WSEarlyData")
			}
			q.Set("ed", values[0])
			pathQuery.Del("ed")
			path.RawQuery = pathQuery.Encode()
			v.WSPath = path.String()
		}
	}
	if v.Network == "grpc" {
		v.GRPCServiceName = q.Get("serviceName")
		v.GRPCAuthority = q.Get("authority")
		if q.Has("mode") {
			if q.Get("mode") != "multi" {
				return Profile{}, problem.New("choice_invalid", "unsupported VLESS gRPC mode").At("GRPCMultiMode").Arg("allowed", "multi")
			}
			v.GRPCMultiMode = true
		}
	} else if v.Network == "xhttp" {
		v.XHTTPPath, v.XHTTPHost, v.XHTTPMode = q.Get("path"), q.Get("host"), q.Get("mode")
		if q.Has("extra") {
			v.XHTTPOptions, err = ParseXHTTPExtra(q.Get("extra"))
			if err != nil {
				return Profile{}, err
			}
		}
		v.WSPath, v.WSHost = "", ""
	}
	if q.Has("ed") {
		v.WSEarlyData, err = strconv.Atoi(q.Get("ed"))
		if err != nil {
			return Profile{}, problem.New("number_invalid", "invalid VLESS WebSocket early data").At("WSEarlyData")
		}
		if v.WSEarlyData == 0 {
			return Profile{}, problem.New("number_out_of_range", "invalid VLESS WebSocket early data").At("WSEarlyData").Arg("min", "1").Arg("max", "8192")
		}
	}
	if err := v.Validate(u.Hostname(), port); err != nil {
		return Profile{}, err
	}
	e := Endpoint{Host: u.Hostname(), Port: port}
	return Profile{Type: "vless", Name: u.Fragment, TCP: e, UDP: e, VLESS: v}, nil
}

func (e Endpoint) Validate() error {
	if err := endpointProblem("invalid server endpoint", e.Host, e.Port); err != nil {
		return err
	}
	switch e.Cipher {
	case "chacha20-ietf-poly1305", "aes-128-gcm", "aes-192-gcm", "aes-256-gcm":
	case "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305":
		if e.Prefix != "" {
			return problem.New("option_not_supported", "Shadowsocks 2022 does not support salt prefixes").At("Prefix").Also("Method").Arg("type", "Shadowsocks 2022")
		}
		if _, err := ParseSS2022Keys(e.Cipher, e.Secret); err != nil {
			return err
		}
	default:
		return problem.New("choice_invalid", "unsupported Shadowsocks cipher").On("Method", e.Cipher).Arg("allowed", "chacha20-ietf-poly1305, aes-128-gcm, aes-192-gcm, aes-256-gcm, 2022-blake3-aes-128-gcm, 2022-blake3-aes-256-gcm, 2022-blake3-chacha20-poly1305")
	}
	if e.Secret == "" {
		return problem.New("value_required", "empty password").On("Password", "")
	}
	return nil
}
func decode(s string) (string, error) {
	for _, e := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		if b, err := e.DecodeString(s); err == nil {
			return string(b), nil
		}
	}
	return "", problem.New("uri_invalid", "invalid encoded credentials")
}
func ParseSS(raw string) (Profile, error) {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, "ss://") {
		return Profile{}, problem.New("uri_scheme_invalid", "expected ss key").Arg("schemes", "ss://")
	}
	body := strings.TrimPrefix(raw, "ss://")
	if !strings.Contains(strings.SplitN(body, "#", 2)[0], "@") {
		parts := strings.SplitN(body, "#", 2)
		decoded, err := decode(parts[0])
		if err != nil {
			return Profile{}, err
		}
		at := strings.LastIndex(decoded, "@")
		if at < 0 {
			return Profile{}, problem.New("uri_invalid", "invalid ss URI")
		}
		// Protect base64 key characters and password delimiters from URL parsing.
		raw = "ss://" + base64.RawURLEncoding.EncodeToString([]byte(decoded[:at])) + decoded[at:]
		if len(parts) == 2 {
			raw += "#" + parts[1]
		}
	}
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return Profile{}, problem.New("uri_invalid", "invalid ss URI")
	}
	if u.Path != "" && u.Path != "/" {
		return Profile{}, problem.New("uri_invalid", "invalid ss path")
	}
	cipher := u.User.Username()
	secret, plain := u.User.Password()
	if !plain {
		decoded, err := decode(cipher)
		if err != nil {
			return Profile{}, err
		}
		var ok bool
		cipher, secret, ok = strings.Cut(decoded, ":")
		if !ok {
			return Profile{}, problem.New("uri_invalid", "invalid credentials")
		}
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return Profile{}, problem.New("uri_invalid", "invalid options")
	}
	for k, v := range q {
		if (k != "outline" && k != "prefix" && k != "plugin") || len(v) != 1 {
			return Profile{}, problem.New("uri_option_unsupported", "unsupported ss option")
		}
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return Profile{}, problem.New("port_invalid", "invalid port").At("Port")
	}
	e := Endpoint{u.Hostname(), port, cipher, secret, q.Get("prefix")}
	if err := e.Validate(); err != nil {
		return Profile{}, err
	}
	p := Profile{Name: u.Fragment, TCP: e, UDP: e}
	if q.Has("plugin") {
		p.SSPlugin, err = parseSSPluginQuery(q.Get("plugin"))
		if err != nil {
			return Profile{}, err
		}
		p.UDP = Endpoint{}
	}
	return p, nil
}

// ParseSOCKS5 accepts a SOCKS5 URI without leaking credentials in errors.
func ParseSOCKS5(raw string) (Profile, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "socks5" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return Profile{}, problem.New("uri_invalid", "invalid socks5 URI")
	}
	if u.Hostname() == "" {
		return Profile{}, problem.New("value_required", "invalid socks5 URI").On("Server", "")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return Profile{}, problem.New("port_invalid", "invalid socks5 port").At("Port")
	}
	username, password := "", ""
	if u.User != nil {
		username = u.User.Username()
		var ok bool
		password, ok = u.User.Password()
		if !ok || username == "" || password == "" {
			return Profile{}, credentialsProblem("socks5 username and password must both be set", username, password)
		}
	}
	if len(username) > 255 {
		return Profile{}, problem.New("value_too_long", "socks5 credentials are too long").At("Username").Arg("max", "255")
	}
	if len(password) > 255 {
		return Profile{}, problem.New("value_too_long", "socks5 credentials are too long").On("Password", password).Arg("max", "255")
	}
	e := Endpoint{Host: u.Hostname(), Port: port, Secret: password}
	if e.Host == "" || strings.ContainsAny(e.Host, " /\t\r\n") {
		return Profile{}, problem.New("host_invalid", "invalid socks5 server endpoint").On("Server", e.Host)
	}
	return Profile{Type: "socks5", Username: username, TCP: e, UDP: e}, nil
}

// ParseHTTPConnect accepts an HTTP proxy URI without exposing credentials in errors.
func ParseHTTPConnect(raw string) (Profile, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Opaque != "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return Profile{}, problem.New("uri_invalid", "invalid HTTP proxy URI")
	}
	if u.Hostname() == "" {
		return Profile{}, problem.New("value_required", "invalid HTTP proxy URI").On("Server", "")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return Profile{}, problem.New("port_invalid", "invalid HTTP proxy endpoint").At("Port")
	}
	if strings.ContainsAny(u.Hostname(), " /\t\r\n") {
		return Profile{}, problem.New("host_invalid", "invalid HTTP proxy endpoint").On("Server", u.Hostname())
	}
	username, password := "", ""
	if u.User != nil {
		const message = "invalid HTTP proxy credentials"
		username = u.User.Username()
		var ok bool
		password, ok = u.User.Password()
		if !ok || username == "" || password == "" {
			return Profile{}, credentialsProblem(message, username, password)
		}
		if strings.ContainsAny(username, ":\r\n") {
			return Profile{}, problem.New("value_has_invalid_characters", message).At("Username")
		}
		if strings.ContainsAny(password, "\r\n") {
			return Profile{}, problem.New("value_has_invalid_characters", message).On("Password", password)
		}
	}
	e := Endpoint{Host: u.Hostname(), Port: port, Secret: password}
	p := Profile{Type: "http", Username: username, TCP: e}
	if u.Scheme == "https" {
		p.HTTPServerName = u.Hostname()
	}
	return p, nil
}

type wireEndpoint struct {
	Type    string `yaml:"$type"`
	Address string `yaml:"endpoint"`
	Cipher  string `yaml:"cipher"`
	Secret  string `yaml:"secret"`
	Prefix  string `yaml:"prefix"`
}
type wireConfig struct {
	Plugin     string `yaml:"plugin"`
	PluginOpts string `yaml:"plugin_opts"`
	Server     string `yaml:"server"`
	Port       int    `yaml:"server_port"`
	Password   string `yaml:"password"`
	Method     string `yaml:"method"`
	Prefix     string `yaml:"prefix"`
	Transport  *struct {
		Type string       `yaml:"$type"`
		TCP  wireEndpoint `yaml:"tcp"`
		UDP  wireEndpoint `yaml:"udp"`
	} `yaml:"transport"`
}

// ParseConfig rejects unknown features rather than silently changing semantics.
func ParseConfig(b []byte) (Profile, error) {
	if len(b) > maxBytes {
		return Profile{}, problem.New("file_too_large", "config too large").Arg("limit", "64 KiB")
	}
	if strings.HasPrefix(strings.TrimSpace(string(b)), "ss://") {
		return ParseSS(string(b))
	}
	var c wireConfig
	d := yaml.NewDecoder(strings.NewReader(string(b)))
	d.KnownFields(true)
	if err := d.Decode(&c); err != nil {
		return Profile{}, problem.New("ssconf_config_invalid", "invalid or unsupported config")
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return Profile{}, problem.New("ssconf_config_invalid", "expected one config document")
	}
	if c.Transport == nil {
		e := Endpoint{c.Server, c.Port, c.Method, c.Password, c.Prefix}
		if err := e.Validate(); err != nil {
			return Profile{}, err
		}
		plugin, err := ParseSSPlugin(c.Plugin, c.PluginOpts)
		if err != nil {
			return Profile{}, err
		}
		p := Profile{TCP: e, UDP: e, SSPlugin: plugin}
		if plugin != nil {
			p.UDP = Endpoint{}
		}
		return p, nil
	}
	if c.Server != "" || c.Port != 0 || c.Password != "" || c.Method != "" || c.Prefix != "" || c.Plugin != "" || c.PluginOpts != "" {
		return Profile{}, problem.New("ssconf_config_invalid", "mixed config formats")
	}
	if c.Transport.Type != "tcpudp" {
		return Profile{}, problem.New("ssconf_config_invalid", "unsupported transport")
	}
	convert := func(w wireEndpoint) (Endpoint, error) {
		if w.Type != "shadowsocks" {
			return Endpoint{}, problem.New("ssconf_config_invalid", "unsupported transport")
		}
		host, port, err := net.SplitHostPort(w.Address)
		if err != nil {
			return Endpoint{}, problem.New("ssconf_config_invalid", "invalid endpoint").At("Server")
		}
		n, err := strconv.Atoi(port)
		if err != nil {
			return Endpoint{}, problem.New("port_invalid", "invalid port").At("Port")
		}
		e := Endpoint{host, n, w.Cipher, w.Secret, w.Prefix}
		return e, e.Validate()
	}
	tcp, err := convert(c.Transport.TCP)
	if err != nil {
		return Profile{}, err
	}
	udp, err := convert(c.Transport.UDP)
	if err != nil {
		return Profile{}, err
	}
	return Profile{TCP: tcp, UDP: udp}, nil
}

type Resolver struct{ client *http.Client }

type unavailableError struct{ status int }

func (e unavailableError) Error() string {
	return fmt.Sprintf("config server returned HTTP %d", e.status)
}

func IsUnavailable(err error) bool {
	var unavailable unavailableError
	return errors.As(err, &unavailable)
}

func NewResolver() *Resolver {
	return &Resolver{client: &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 || req.URL.Scheme != "https" || req.URL.User != nil {
			return fmt.Errorf("redirect rejected")
		}
		return nil
	}}}
}

// NewResolverWithTransport preserves HTTPS and redirect restrictions while
// allowing the VPN control plane to use an interface-bound transport.
func NewResolverWithTransport(t http.RoundTripper) *Resolver {
	r := NewResolver()
	r.client.Transport = t
	return r
}
func (r *Resolver) Resolve(ctx context.Context, key string) (Profile, error) {
	key = strings.TrimSpace(key)
	if strings.HasPrefix(key, "anytls://") {
		return ParseAnyTLS(key)
	}
	if strings.HasPrefix(key, "naive+https://") || strings.HasPrefix(key, "naive+quic://") {
		return ParseNaive(key)
	}
	if strings.HasPrefix(key, "ssh://") {
		return ParseSSH(key)
	}
	if strings.HasPrefix(key, "vless://") {
		return ParseVLESS(key)
	}
	if strings.HasPrefix(key, "trojan://") {
		return ParseTrojan(key)
	}
	if strings.HasPrefix(key, "hysteria2://") || strings.HasPrefix(key, "hy2://") {
		return ParseHysteria2(key)
	}
	if strings.HasPrefix(key, "tuic://") {
		return ParseTUIC(key)
	}
	if strings.HasPrefix(key, "vmess://") {
		return ParseVMess(key)
	}
	if strings.HasPrefix(key, "ss://") {
		return ParseSS(key)
	}
	if strings.HasPrefix(key, "socks5://") {
		return ParseSOCKS5(key)
	}
	if strings.HasPrefix(key, "http://") || strings.HasPrefix(key, "https://") {
		return ParseHTTPConnect(key)
	}
	if strings.HasPrefix(key, "masque://") {
		return ParseMASQUE(key)
	}
	_, p, err := r.FetchSSConf(ctx, key)
	return p, err
}

// FetchSSConf returns validated bytes and their parsed profile.
func (r *Resolver) FetchSSConf(ctx context.Context, key string) ([]byte, Profile, error) {
	key = strings.TrimSpace(key)
	if !strings.HasPrefix(key, "ssconf://") {
		return nil, Profile{}, fmt.Errorf("unsupported access key scheme")
	}
	u, err := url.Parse("https://" + strings.TrimPrefix(key, "ssconf://"))
	if err != nil || u.Hostname() == "" || u.User != nil {
		return nil, Profile{}, fmt.Errorf("invalid ssconf URL")
	}
	name := u.Fragment
	u.Fragment = ""
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, Profile{}, fmt.Errorf("invalid config request")
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, Profile{}, fmt.Errorf("could not fetch dynamic config")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusPaymentRequired, http.StatusForbidden, http.StatusNotFound, http.StatusGone:
			return nil, Profile{}, unavailableError{resp.StatusCode}
		}
		return nil, Profile{}, fmt.Errorf("config server returned HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, Profile{}, fmt.Errorf("could not read config")
	}
	p, err := ParseConfig(b)
	if err == nil && name != "" {
		p.Name = name
	}
	if err != nil {
		return nil, Profile{}, err
	}
	return b, p, nil
}

// ParseSS2022Keys returns identity keys followed by the user key.
// Errors never include credentials. SIP023 chains require an AES method.
func ParseSS2022Keys(method, secret string) ([][]byte, error) {
	size := 32
	switch method {
	case "2022-blake3-aes-128-gcm":
		size = 16
	case "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305":
	default:
		return nil, problem.New("choice_invalid", "unsupported Shadowsocks 2022 method").On("Method", method).Arg("allowed", "2022-blake3-aes-128-gcm, 2022-blake3-aes-256-gcm, 2022-blake3-chacha20-poly1305")
	}
	parts := strings.Split(secret, ":")
	if len(parts) > 1 && method == "2022-blake3-chacha20-poly1305" {
		return nil, problem.New("ss2022_identity_requires_aes", "Shadowsocks 2022 identity chains require an AES method").On("Password", secret).Also("Method")
	}
	keys := make([][]byte, len(parts))
	for i, part := range parts {
		key, err := base64.StdEncoding.Strict().DecodeString(part)
		if err != nil || len(key) != size || strings.ContainsAny(part, "\r\n") {
			return nil, problem.New("ss2022_key_invalid", "invalid Shadowsocks 2022 key").On("Password", secret).ArgInt("bytes", size)
		}
		keys[i] = key
	}
	return keys, nil
}

// endpointProblem names the invalid part of a server endpoint, or returns nil.
func endpointProblem(message, host string, port int) error {
	if host == "" {
		return problem.New("value_required", message).On("Server", host)
	}
	if strings.ContainsAny(host, " /\t\r\n") {
		return problem.New("host_invalid", message).On("Server", host)
	}
	if port < 1 || port > 65535 {
		return problem.New("port_invalid", message).At("Port")
	}
	return nil
}

// passwordProblem rejects an empty password or one with line breaks.
func passwordProblem(message, password string) error {
	if password == "" {
		return problem.New("value_required", message).On("Password", password)
	}
	if strings.ContainsAny(password, "\r\n") {
		return problem.New("value_has_invalid_characters", message).On("Password", password)
	}
	return nil
}

// serverNameProblem rejects an empty TLS server name or one with spaces or slashes.
func serverNameProblem(message, name string) error {
	if name == "" {
		return problem.New("value_required", message).On("ServerName", name)
	}
	if strings.ContainsAny(name, " /\t\r\n") {
		return problem.New("server_name_invalid", message).On("ServerName", name)
	}
	return nil
}

// credentialsProblem reports the missing half of a user name and password pair.
func credentialsProblem(message, username, password string) error {
	if username == "" {
		return problem.New("credentials_incomplete", message).On("Username", username).Also("Password")
	}
	return problem.New("credentials_incomplete", message).On("Password", password).Also("Username")
}

// wsPathProblem validates an optional WebSocket path. Early data belongs in
// WSEarlyData, never in the path query.
func wsPathProblem(message, value string) error {
	if value == "" {
		return nil
	}
	path, err := url.ParseRequestURI(value)
	if err != nil || path.IsAbs() || !strings.HasPrefix(value, "/") || strings.ContainsAny(value, "#\\\r\n") {
		return problem.New("path_invalid", message).At("WSPath")
	}
	if path.Query().Has("ed") {
		return problem.New("path_early_data_unsupported", message).At("WSPath")
	}
	return nil
}

// alpnProblem reports an ALPN list that the transport does not accept.
func alpnProblem(message, network string) error {
	allowed := map[string]string{"ws": "http/1.1", "grpc": "h2", "xhttp": "h2; h3; http/1.1; h2,http/1.1"}[network]
	if allowed == "" {
		return problem.New("value_invalid", message).At("ALPN")
	}
	return problem.New("alpn_invalid", message).At("ALPN").Also("Network").Arg("allowed", allowed)
}

// requiresTransport reports an option that is set for the wrong transport.
func requiresTransport(message, transport, field string) error {
	return problem.New("option_requires_transport", message).At(field).Also("Network").Arg("transport", transport)
}

// vlessTransportOptionsProblem rejects VLESS URI options that the selected
// transport does not use.
func vlessTransportOptionsProblem(q url.Values) error {
	const message = "VLESS option does not match transport"
	typ := q.Get("type")
	switch {
	case q.Has("serviceName") && typ != "grpc":
		return requiresTransport(message, "gRPC", "GRPCServiceName")
	case q.Has("authority") && typ != "grpc":
		return requiresTransport(message, "gRPC", "GRPCAuthority")
	case q.Has("mode") && typ != "xhttp" && typ != "grpc":
		if mode := q.Get("mode"); mode == "multi" || mode == "gun" {
			return requiresTransport(message, "gRPC", "GRPCMultiMode")
		}
		return requiresTransport(message, "XHTTP", "XHTTPMode")
	case q.Has("extra") && typ != "xhttp":
		return requiresTransport(message, "XHTTP", "XHTTPExtra")
	case (q.Has("path") || q.Has("host")) && typ != "ws" && typ != "xhttp":
		return requiresTransport(message, "WebSocket / XHTTP", firstSet([]string{"WSPath", "WSHost"}, q.Has("path"), q.Has("host")))
	}
	return nil
}

// firstSet returns the first field whose paired flag is true.
func firstSet(fields []string, set ...bool) string {
	for i, ok := range set {
		if ok {
			return fields[i]
		}
	}
	return ""
}
