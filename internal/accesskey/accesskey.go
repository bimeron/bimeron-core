package accesskey

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"gopkg.in/yaml.v3"
	"io"
	"net"
	"net/http"
	"net/url"
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
