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
	Name     string
	TCP      Endpoint
	UDP      Endpoint
	Type     string // Empty means Shadowsocks for existing API callers.
	Username string // SOCKS5 only; Secret contains its password.
	VLESS    VLESS
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
	if host == "" || strings.ContainsAny(host, " /\t\r\n") || port < 1 || port > 65535 {
		return fmt.Errorf("invalid VLESS server endpoint")
	}
	if !uuidPattern.MatchString(v.ID) {
		return fmt.Errorf("invalid VLESS user ID")
	}
	if v.Encryption != "none" {
		return fmt.Errorf("unsupported VLESS transport, security, encryption or flow")
	}
	vision := v.Flow == "xtls-rprx-vision" || v.Flow == "xtls-rprx-vision-udp443"
	if !((v.Network == "tcp" && v.Security == "reality" && (vision || v.Flow == "")) || (v.Network == "tcp" && v.Security == "tls" && v.Flow == "") || (v.Network == "ws" && v.Security == "tls" && v.Flow == "") || (v.Network == "grpc" && (v.Security == "tls" || v.Security == "reality") && v.Flow == "") || (v.Network == "xhttp" && v.Security == "tls" && v.Flow == "" && (v.XHTTPMode == "packet-up" || v.XHTTPMode == "stream-up" || v.XHTTPMode == "auto")) || (v.Network == "xhttp" && v.Security == "reality" && v.Flow == "" && (v.XHTTPMode == "stream-one" || v.XHTTPMode == "stream-up" || v.XHTTPMode == "auto"))) {
		return fmt.Errorf("unsupported VLESS transport, security or flow")
	}
	if strings.ContainsAny(v.ServerName, " /\t\r\n") {
		return fmt.Errorf("invalid VLESS server name")
	}
	if v.Fingerprint != "" {
		switch v.Fingerprint {
		case "chrome", "firefox", "safari", "ios", "android", "edge":
		default:
			return fmt.Errorf("unsupported VLESS fingerprint")
		}
	}
	if v.Security == "reality" {
		if v.ServerName == "" || v.Fingerprint == "" || v.WSPath != "" || v.WSHost != "" || (v.Network == "tcp" && v.ALPN != "") || ((v.Network == "xhttp" || v.Network == "grpc") && v.ALPN != "" && v.ALPN != "h2") {
			return fmt.Errorf("invalid VLESS REALITY settings")
		}
		key, err := base64.RawURLEncoding.DecodeString(v.PublicKey)
		if err != nil || len(key) != 32 {
			return fmt.Errorf("invalid VLESS REALITY public key")
		}
		if len(v.ShortID) > 16 || len(v.ShortID)%2 != 0 {
			return fmt.Errorf("invalid VLESS REALITY short ID")
		}
		if _, err := hex.DecodeString(v.ShortID); err != nil {
			return fmt.Errorf("invalid VLESS REALITY short ID")
		}
	} else if v.PublicKey != "" || v.ShortID != "" || v.SpiderX != "" {
		return fmt.Errorf("REALITY options require security=reality")
	}
	if v.Network != "ws" && (v.WSPath != "" || v.WSHost != "") {
		return fmt.Errorf("WebSocket options require type=ws")
	}
	if v.Network == "ws" {
		if v.WSPath != "" {
			path, err := url.ParseRequestURI(v.WSPath)
			if err != nil || path.IsAbs() || !strings.HasPrefix(v.WSPath, "/") || strings.ContainsAny(v.WSPath, "#\\\r\n") || path.Query().Has("ed") {
				return fmt.Errorf("invalid or unsupported VLESS WebSocket path")
			}
		}
		if v.WSHost != "" {
			host, err := url.Parse("https://" + v.WSHost)
			if err != nil || host.Hostname() == "" || host.User != nil || host.Path != "" || host.RawQuery != "" || host.Fragment != "" {
				return fmt.Errorf("invalid VLESS WebSocket host")
			}
		}
	}
	if v.WSEarlyData < 0 || v.WSEarlyData > 8192 || (v.Network != "ws" && v.WSEarlyData != 0) {
		return fmt.Errorf("invalid VLESS WebSocket early data")
	}
	if v.Network != "grpc" && (v.GRPCServiceName != "" || v.GRPCAuthority != "" || v.GRPCMultiMode) {
		return fmt.Errorf("gRPC options require type=grpc")
	}
	if v.Network == "grpc" && (v.GRPCServiceName == "" || strings.ContainsAny(v.GRPCServiceName, "?\\# \t\r\n") || (strings.Contains(v.GRPCServiceName, "/") && (!strings.HasPrefix(v.GRPCServiceName, "/") || strings.HasSuffix(v.GRPCServiceName, "/") || strings.Contains(v.GRPCServiceName, "//")))) {
		return fmt.Errorf("invalid VLESS gRPC service name")
	}
	if v.GRPCAuthority != "" && (strings.ContainsAny(v.GRPCAuthority, " /\\@?#\t\r\n") || strings.HasPrefix(v.GRPCAuthority, ":")) {
		return fmt.Errorf("invalid VLESS gRPC authority")
	}
	if v.Network != "xhttp" && (v.XHTTPPath != "" || v.XHTTPHost != "" || v.XHTTPMode != "" || v.XHTTPOptions != nil) {
		return fmt.Errorf("XHTTP options require type=xhttp")
	}
	if v.Network == "xhttp" {
		if err := v.XHTTPOptions.Validate(v.XHTTPMode, v.Security, v.ALPN); err != nil {
			return err
		}
		if v.ALPN == "h3" && (v.Security != "tls" || v.Fingerprint != "") {
			return fmt.Errorf("HTTP/3 requires TLS without a TLS fingerprint")
		}
		if v.XHTTPPath != "" {
			path, err := url.ParseRequestURI(v.XHTTPPath)
			if err != nil || path.IsAbs() || !strings.HasPrefix(v.XHTTPPath, "/") || strings.ContainsAny(v.XHTTPPath, "#\\\r\n") {
				return fmt.Errorf("invalid VLESS XHTTP path")
			}
		}
		if v.XHTTPHost != "" {
			host, err := url.Parse("https://" + v.XHTTPHost)
			if err != nil || host.Hostname() == "" || host.User != nil || host.Path != "" || host.RawQuery != "" || host.Fragment != "" || strings.ContainsAny(v.XHTTPHost, " \t\r\n") {
				return fmt.Errorf("invalid VLESS XHTTP host")
			}
		}
	}
	if v.ALPN != "" {
		for _, protocol := range strings.Split(v.ALPN, ",") {
			if protocol == "" || strings.ContainsAny(protocol, " \t\r\n") || (v.Network == "ws" && protocol != "http/1.1") || (v.Network == "grpc" && protocol != "h2") || (v.Network == "xhttp" && protocol != "h2" && protocol != "h3") || (v.Network == "xhttp" && strings.Contains(v.ALPN, ",")) {
				return fmt.Errorf("invalid VLESS ALPN")
			}
		}
	}
	return nil
}

// ParseVLESS never includes the input URI or credentials in errors.
func ParseVLESS(raw string) (Profile, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "vless" || u.User == nil || u.Hostname() == "" || u.Path != "" {
		return Profile{}, fmt.Errorf("invalid VLESS URI")
	}
	if _, ok := u.User.Password(); ok {
		return Profile{}, fmt.Errorf("invalid VLESS user ID")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return Profile{}, fmt.Errorf("invalid VLESS port")
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return Profile{}, fmt.Errorf("invalid VLESS options")
	}
	allowed := map[string]bool{"encryption": true, "flow": true, "type": true, "security": true, "sni": true, "pbk": true, "sid": true, "fp": true, "spx": true, "alpn": true, "path": true, "host": true, "ed": true, "serviceName": true, "authority": true, "mode": true, "extra": true}
	for k, values := range q {
		if !allowed[k] || len(values) != 1 {
			return Profile{}, fmt.Errorf("unsupported or duplicate VLESS option")
		}
	}
	if ((q.Has("serviceName") || q.Has("authority")) && q.Get("type") != "grpc") || (q.Has("mode") && q.Get("type") != "xhttp" && q.Get("type") != "grpc") || (q.Has("extra") && q.Get("type") != "xhttp") || ((q.Has("path") || q.Has("host")) && q.Get("type") != "ws" && q.Get("type") != "xhttp") {
		return Profile{}, fmt.Errorf("VLESS option does not match transport")
	}
	v := VLESS{ID: u.User.Username(), Flow: q.Get("flow"), Network: q.Get("type"), Security: q.Get("security"), Encryption: q.Get("encryption"), ServerName: q.Get("sni"), PublicKey: q.Get("pbk"), ShortID: q.Get("sid"), Fingerprint: q.Get("fp"), SpiderX: q.Get("spx"), ALPN: q.Get("alpn"), WSPath: q.Get("path"), WSHost: q.Get("host")}
	if v.Network == "ws" && v.WSPath != "" {
		path, pathErr := url.ParseRequestURI(v.WSPath)
		if pathErr != nil {
			return Profile{}, fmt.Errorf("invalid VLESS WebSocket path")
		}
		pathQuery := path.Query()
		if values, ok := pathQuery["ed"]; ok {
			if q.Has("ed") || len(values) != 1 {
				return Profile{}, fmt.Errorf("duplicate VLESS WebSocket early data")
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
				return Profile{}, fmt.Errorf("unsupported VLESS gRPC mode")
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
		if err != nil || v.WSEarlyData == 0 {
			return Profile{}, fmt.Errorf("invalid VLESS WebSocket early data")
		}
	}
	if err := v.Validate(u.Hostname(), port); err != nil {
		return Profile{}, err
	}
	e := Endpoint{Host: u.Hostname(), Port: port}
	return Profile{Type: "vless", Name: u.Fragment, TCP: e, UDP: e, VLESS: v}, nil
}

func (e Endpoint) Validate() error {
	if e.Host == "" || strings.ContainsAny(e.Host, " /\t\r\n") || e.Port < 1 || e.Port > 65535 {
		return fmt.Errorf("invalid server endpoint")
	}
	switch e.Cipher {
	case "chacha20-ietf-poly1305", "aes-128-gcm", "aes-192-gcm", "aes-256-gcm":
	default:
		return fmt.Errorf("unsupported Shadowsocks cipher")
	}
	if e.Secret == "" {
		return fmt.Errorf("empty password")
	}
	return nil
}
func decode(s string) (string, error) {
	for _, e := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		if b, err := e.DecodeString(s); err == nil {
			return string(b), nil
		}
	}
	return "", fmt.Errorf("invalid encoded credentials")
}
func ParseSS(raw string) (Profile, error) {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, "ss://") {
		return Profile{}, fmt.Errorf("expected ss key")
	}
	body := strings.TrimPrefix(raw, "ss://")
	if !strings.Contains(strings.SplitN(body, "#", 2)[0], "@") {
		parts := strings.SplitN(body, "#", 2)
		decoded, err := decode(parts[0])
		if err != nil {
			return Profile{}, err
		}
		raw = "ss://" + decoded
		if len(parts) == 2 {
			raw += "#" + parts[1]
		}
	}
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return Profile{}, fmt.Errorf("invalid ss URI")
	}
	if u.Path != "" && u.Path != "/" {
		return Profile{}, fmt.Errorf("invalid ss path")
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
			return Profile{}, fmt.Errorf("invalid credentials")
		}
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return Profile{}, fmt.Errorf("invalid options")
	}
	for k, v := range q {
		if (k != "outline" && k != "prefix") || len(v) != 1 {
			return Profile{}, fmt.Errorf("unsupported ss option")
		}
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return Profile{}, fmt.Errorf("invalid port")
	}
	e := Endpoint{u.Hostname(), port, cipher, secret, q.Get("prefix")}
	if err := e.Validate(); err != nil {
		return Profile{}, err
	}
	return Profile{Name: u.Fragment, TCP: e, UDP: e}, nil
}

// ParseSOCKS5 accepts a SOCKS5 URI without leaking credentials in errors.
func ParseSOCKS5(raw string) (Profile, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "socks5" || u.Hostname() == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return Profile{}, fmt.Errorf("invalid socks5 URI")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return Profile{}, fmt.Errorf("invalid socks5 port")
	}
	username, password := "", ""
	if u.User != nil {
		username = u.User.Username()
		var ok bool
		password, ok = u.User.Password()
		if !ok || username == "" || password == "" {
			return Profile{}, fmt.Errorf("socks5 username and password must both be set")
		}
	}
	if len(username) > 255 || len(password) > 255 {
		return Profile{}, fmt.Errorf("socks5 credentials are too long")
	}
	e := Endpoint{Host: u.Hostname(), Port: port, Secret: password}
	if e.Host == "" || strings.ContainsAny(e.Host, " /\t\r\n") {
		return Profile{}, fmt.Errorf("invalid socks5 server endpoint")
	}
	return Profile{Type: "socks5", Username: username, TCP: e, UDP: e}, nil
}

type wireEndpoint struct {
	Type    string `yaml:"$type"`
	Address string `yaml:"endpoint"`
	Cipher  string `yaml:"cipher"`
	Secret  string `yaml:"secret"`
	Prefix  string `yaml:"prefix"`
}
type wireConfig struct {
	Server    string `yaml:"server"`
	Port      int    `yaml:"server_port"`
	Password  string `yaml:"password"`
	Method    string `yaml:"method"`
	Prefix    string `yaml:"prefix"`
	Transport *struct {
		Type string       `yaml:"$type"`
		TCP  wireEndpoint `yaml:"tcp"`
		UDP  wireEndpoint `yaml:"udp"`
	} `yaml:"transport"`
}

// ParseConfig rejects unknown features rather than silently changing semantics.
func ParseConfig(b []byte) (Profile, error) {
	if len(b) > maxBytes {
		return Profile{}, fmt.Errorf("config too large")
	}
	if strings.HasPrefix(strings.TrimSpace(string(b)), "ss://") {
		return ParseSS(string(b))
	}
	var c wireConfig
	d := yaml.NewDecoder(strings.NewReader(string(b)))
	d.KnownFields(true)
	if err := d.Decode(&c); err != nil {
		return Profile{}, fmt.Errorf("invalid or unsupported config")
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return Profile{}, fmt.Errorf("expected one config document")
	}
	if c.Transport == nil {
		e := Endpoint{c.Server, c.Port, c.Method, c.Password, c.Prefix}
		if err := e.Validate(); err != nil {
			return Profile{}, err
		}
		return Profile{TCP: e, UDP: e}, nil
	}
	if c.Server != "" || c.Port != 0 || c.Password != "" || c.Method != "" || c.Prefix != "" {
		return Profile{}, fmt.Errorf("mixed config formats")
	}
	if c.Transport.Type != "tcpudp" {
		return Profile{}, fmt.Errorf("unsupported transport")
	}
	convert := func(w wireEndpoint) (Endpoint, error) {
		if w.Type != "shadowsocks" {
			return Endpoint{}, fmt.Errorf("unsupported transport")
		}
		host, port, err := net.SplitHostPort(w.Address)
		if err != nil {
			return Endpoint{}, fmt.Errorf("invalid endpoint")
		}
		n, err := strconv.Atoi(port)
		if err != nil {
			return Endpoint{}, fmt.Errorf("invalid port")
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
	if strings.HasPrefix(key, "vless://") {
		return ParseVLESS(key)
	}
	if strings.HasPrefix(key, "ss://") {
		return ParseSS(key)
	}
	if strings.HasPrefix(key, "socks5://") {
		return ParseSOCKS5(key)
	}
	if !strings.HasPrefix(key, "ssconf://") {
		return Profile{}, fmt.Errorf("expected ss, ssconf, or socks5 key")
	}
	u, err := url.Parse("https://" + strings.TrimPrefix(key, "ssconf://"))
	if err != nil || u.Hostname() == "" || u.User != nil {
		return Profile{}, fmt.Errorf("invalid ssconf URL")
	}
	name := u.Fragment
	u.Fragment = ""
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return Profile{}, fmt.Errorf("invalid config request")
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return Profile{}, fmt.Errorf("could not fetch dynamic config")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusPaymentRequired, http.StatusForbidden, http.StatusNotFound, http.StatusGone:
			return Profile{}, unavailableError{resp.StatusCode}
		}
		return Profile{}, fmt.Errorf("config server returned HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return Profile{}, fmt.Errorf("could not read config")
	}
	p, err := ParseConfig(b)
	if err == nil && name != "" {
		p.Name = name
	}
	return p, err
}
