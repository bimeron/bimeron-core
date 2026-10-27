// Package config defines Bimeron's versioned, WireGuard-style .conf format.
package config

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"bimeron/internal/accesskey"
	"bimeron/internal/dnsconfig"
	"bimeron/internal/routing"
)

const maxSize = 64 * 1024

type File struct {
	Version int
	Name    string
	Access  Access
	Tunnel  Tunnel
	Routing routing.Config
	key     string
	profile *accesskey.Profile
}
type Access struct {
	SS              string
	SSConf          string
	SOCKS5          string
	VLESS           string
	VMess           string
	Trojan          string
	Hysteria2       string
	SSH             string
	TUIC            string
	Key             string
	KeyFile         string
	Type            string
	Parameters      *Parameters
	Username        string
	IdentityFile    string
	KnownHostsFile  string
	VLESSParameters *accesskey.VLESS
	ServerName      string
	xhttpExtraUsed  bool
	xhttpFieldsUsed bool
}
type Parameters struct {
	Server   string
	Port     int
	Method   string
	Password string
	Prefix   string
}
type Tunnel struct {
	KillSwitch bool
	IPv6       string
	Mode       string
	Name       string
	MTU        int
	DNS        string
	Listen     string
}

var interfaceName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,31}$`)

func readFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("could not read configuration or key file")
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxSize+1))
	if err != nil || len(b) > maxSize {
		return nil, fmt.Errorf("configuration or key file exceeds size limit or cannot be read")
	}
	return b, nil
}
func parse(b []byte) (*File, error) {
	if !utf8.Valid(b) {
		return nil, fmt.Errorf("config must be UTF-8")
	}
	c := &File{Tunnel: Tunnel{Mode: "vpn", IPv6: "enable", Name: "Bimeron", MTU: 1420, DNS: "1.1.1.1", Listen: "127.0.0.1:1080"}, Routing: routing.Config{Default: routing.Proxy}}
	section := ""
	sections := map[string]bool{}
	fields := map[string]bool{}
	scanner := bufio.NewScanner(strings.NewReader(strings.TrimPrefix(string(b), "\ufeff")))
	scanner.Buffer(make([]byte, 4096), maxSize+1)
	line := 0
	for scanner.Scan() {
		line++
		text := strings.TrimSpace(scanner.Text())
		if text == "" || strings.HasPrefix(text, "#") || strings.HasPrefix(text, ";") {
			continue
		}
		syntax := func() error { return fmt.Errorf("invalid configuration at line %d", line) }
		if strings.HasPrefix(text, "[") {
			if !strings.HasSuffix(text, "]") {
				return nil, syntax()
			}
			section = strings.TrimSpace(text[1 : len(text)-1])
			switch section {
			case "Profile", "AccessKey", "Interface", "Routing":
				if sections[section] {
					return nil, fmt.Errorf("duplicate section at line %d", line)
				}
				sections[section] = true
			case "Rule":
				c.Routing.Rules = append(c.Routing.Rules, routing.Rule{})
			default:
				return nil, fmt.Errorf("unknown section at line %d", line)
			}
			fields = map[string]bool{}
			continue
		}
		key, value, ok := strings.Cut(text, "=")
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if !ok || section == "" || key == "" {
			return nil, syntax()
		}
		if fields[key] {
			return nil, fmt.Errorf("duplicate option at line %d", line)
		}
		fields[key] = true
		// Comments must occupy their own line. URL fragments, semicolons and equals
		// signs inside credentials remain intact. Quoted values support Go escapes.
		if strings.HasPrefix(value, `"`) {
			decoded, err := strconv.Unquote(value)
			if err != nil {
				return nil, syntax()
			}
			value = decoded
		}
		if value == "" && key != "Name" && key != "Prefix" {
			return nil, syntax()
		}
		number := func() (int, error) {
			n, err := strconv.Atoi(value)
			if err != nil {
				return 0, fmt.Errorf("invalid number at line %d", line)
			}
			return n, nil
		}
		recognized := true
		var err error
		switch section {
		case "Profile":
			switch key {
			case "Version":
				c.Version, err = number()
			case "Name":
				c.Name = value
			default:
				recognized = false
			}
		case "Interface":
			switch key {
			case "KillSwitch":
				if value != "true" && value != "false" {
					return nil, fmt.Errorf("[Interface] KillSwitch must be true or false")
				}
				c.Tunnel.KillSwitch = value == "true"
			case "Mode":
				c.Tunnel.Mode = value
			case "Name":
				c.Tunnel.Name = value
			case "MTU":
				c.Tunnel.MTU, err = number()
			case "IPv6":
				c.Tunnel.IPv6 = value
			case "DNS":
				c.Tunnel.DNS = value
			case "Listen":
				c.Tunnel.Listen = value
			default:
				recognized = false
			}
		case "AccessKey":
			switch key {
			case "VLESS":
				c.Access.VLESS = value
			case "VMess":
				c.Access.VMess = value
			case "Trojan":
				c.Access.Trojan = value
			case "Hysteria2":
				c.Access.Hysteria2 = value
			case "SSH":
				c.Access.SSH = value
			case "TUIC":
				c.Access.TUIC = value
			case "SS":
				c.Access.SS = value
			case "SSConf":
				c.Access.SSConf = value
			case "SOCKS5":
				c.Access.SOCKS5 = value
			case "Type":
				c.Access.Type = value
			case "Username":
				c.Access.Username = value
			case "IdentityFile":
				c.Access.IdentityFile = value
			case "KnownHostsFile":
				c.Access.KnownHostsFile = value
			case "ServerName":
				c.Access.ServerName = value
			case "Key":
				c.Access.Key = value
			case "File":
				c.Access.KeyFile = value
			case "ID", "Encryption", "Flow", "Network", "Security", "PublicKey", "ShortID", "Fingerprint", "SpiderX", "ALPN", "WSPath", "WSHost", "WSEarlyData", "GRPCServiceName", "GRPCAuthority", "GRPCMultiMode", "XHTTPPath", "XHTTPHost", "XHTTPMode":
				if c.Access.VLESSParameters == nil {
					c.Access.VLESSParameters = &accesskey.VLESS{}
				}
				v := c.Access.VLESSParameters
				switch key {
				case "ID":
					v.ID = value
				case "Encryption":
					v.Encryption = value
				case "Flow":
					v.Flow = value
				case "Network":
					v.Network = value
				case "Security":
					v.Security = value
				case "ServerName":
					v.ServerName = value
				case "PublicKey":
					v.PublicKey = value
				case "ShortID":
					v.ShortID = value
				case "Fingerprint":
					v.Fingerprint = value
				case "SpiderX":
					v.SpiderX = value
				case "ALPN":
					v.ALPN = value
				case "WSPath":
					v.WSPath = value
				case "WSHost":
					v.WSHost = value
				case "WSEarlyData":
					v.WSEarlyData, err = number()
				case "GRPCServiceName":
					v.GRPCServiceName = value
				case "GRPCAuthority":
					v.GRPCAuthority = value
				case "GRPCMultiMode":
					if value != "true" && value != "false" {
						return nil, fmt.Errorf("[AccessKey] GRPCMultiMode must be true or false")
					}
					v.GRPCMultiMode = value == "true"
				case "XHTTPPath":
					v.XHTTPPath = value
				case "XHTTPHost":
					v.XHTTPHost = value
				case "XHTTPMode":
					v.XHTTPMode = value
				}
			case "Server", "Port", "Method", "Password", "Prefix":
				if c.Access.Parameters == nil {
					c.Access.Parameters = &Parameters{}
				}
				s := c.Access.Parameters
				switch key {
				case "Server":
					s.Server = value
				case "Port":
					s.Port, err = number()
				case "Method":
					s.Method = value
				case "Password":
					s.Password = value
				case "Prefix":
					s.Prefix = value
				}
			default:
				if key == "XHTTPExtra" || strings.HasPrefix(key, "XHTTP") {
					if c.Access.VLESSParameters == nil {
						c.Access.VLESSParameters = &accesskey.VLESS{}
					}
					v := c.Access.VLESSParameters
					if key == "XHTTPExtra" {
						c.Access.xhttpExtraUsed = true
						v.XHTTPOptions, err = accesskey.ParseXHTTPExtra(value)
					} else {
						c.Access.xhttpFieldsUsed = true
						if v.XHTTPOptions == nil {
							v.XHTTPOptions = &accesskey.XHTTPOptions{}
						}
						err = v.XHTTPOptions.SetXHTTPConfField(key, value)
					}
				} else {
					recognized = false
				}
			}
		case "Routing":
			if key == "Default" {
				c.Routing.Default = routing.Action(value)
			} else {
				recognized = false
			}
		case "Rule":
			r := &c.Routing.Rules[len(c.Routing.Rules)-1]
			switch key {
			case "CIDR":
				r.CIDR = value
			case "Domain":
				r.Domain = value
			case "Action":
				r.Action = routing.Action(value)
			default:
				recognized = false
			}
		}
		if err != nil {
			return nil, err
		}
		if !recognized {
			return nil, fmt.Errorf("unknown option at line %d", line)
		}
	}
	if scanner.Err() != nil {
		return nil, fmt.Errorf("could not parse config")
	}
	return c, nil
}
func Load(path string) (*File, error) {
	b, err := readFile(path)
	if err != nil {
		return nil, err
	}
	return loadBytes(b, path)
}

// ParseData loads an in-memory configuration for sandboxed embedding. File
// sources must be expanded by the host before crossing the process boundary.
func ParseData(b []byte) (*File, error) {
	if len(b) > maxSize {
		return nil, fmt.Errorf("configuration exceeds size limit")
	}
	return loadBytes(b, "")
}
func loadBytes(b []byte, path string) (*File, error) {
	c, err := parse(b)
	if err != nil {
		return nil, err
	}
	if c.Version != 1 {
		return nil, fmt.Errorf("[Profile] Version must be 1")
	}
	resolveSSHPath := func(value string) string {
		if value != "" && path != "" && !filepath.IsAbs(value) && value != "~" && !strings.HasPrefix(value, "~/") && !strings.HasPrefix(value, `~\`) {
			return filepath.Join(filepath.Dir(path), value)
		}
		return value
	}
	if c.Tunnel.Mode != "vpn" && c.Tunnel.Mode != "proxy" {
		return nil, fmt.Errorf("[Interface] Mode must be vpn or proxy")
	}
	if c.Tunnel.KillSwitch && c.Tunnel.Mode != "vpn" {
		return nil, fmt.Errorf("KillSwitch requires Mode = vpn")
	}
	if c.Tunnel.IPv6 != "enable" && c.Tunnel.IPv6 != "disable" {
		return nil, fmt.Errorf("[Interface] IPv6 must be enable or disable")
	}
	if c.Tunnel.Mode == "proxy" && c.Tunnel.IPv6 == "disable" {
		return nil, fmt.Errorf("[Interface] IPv6 = disable requires Mode = vpn")
	}
	if !interfaceName.MatchString(c.Tunnel.Name) {
		return nil, fmt.Errorf("[Interface] Name must start with a letter and contain 1-32 ASCII letters, digits, underscores or hyphens")
	}
	if c.Tunnel.MTU < 1280 || c.Tunnel.MTU > 1500 {
		return nil, fmt.Errorf("[Interface] MTU must be between 1280 and 1500")
	}
	if _, err := dnsconfig.Parse(c.Tunnel.DNS); err != nil {
		return nil, err
	}
	address, err := netip.ParseAddrPort(c.Tunnel.Listen)
	if err != nil || !address.Addr().IsLoopback() || address.Port() == 0 {
		return nil, fmt.Errorf("[Interface] Listen must be a loopback IP and port")
	}
	if _, err := routing.Compile(c.Routing); err != nil {
		return nil, err
	}
	if c.Tunnel.Mode == "vpn" {
		if _, err := c.VPNPolicy(); err != nil {
			return nil, err
		}
	}
	if c.Access.SS != "" && !strings.HasPrefix(c.Access.SS, "ss://") {
		return nil, fmt.Errorf("[AccessKey] SS must start with ss://")
	}
	if c.Access.SSConf != "" && !strings.HasPrefix(c.Access.SSConf, "ssconf://") {
		return nil, fmt.Errorf("[AccessKey] SSConf must start with ssconf://")
	}
	if c.Access.SOCKS5 != "" && !strings.HasPrefix(c.Access.SOCKS5, "socks5://") {
		return nil, fmt.Errorf("[AccessKey] SOCKS5 must start with socks5://")
	}
	if c.Access.VLESS != "" && !strings.HasPrefix(c.Access.VLESS, "vless://") {
		return nil, fmt.Errorf("[AccessKey] VLESS must start with vless://")
	}
	if c.Access.VMess != "" && !strings.HasPrefix(c.Access.VMess, "vmess://") {
		return nil, fmt.Errorf("[AccessKey] VMess must start with vmess://")
	}
	if c.Access.Trojan != "" && !strings.HasPrefix(c.Access.Trojan, "trojan://") {
		return nil, fmt.Errorf("[AccessKey] Trojan must start with trojan://")
	}
	if c.Access.Hysteria2 != "" && !strings.HasPrefix(c.Access.Hysteria2, "hysteria2://") && !strings.HasPrefix(c.Access.Hysteria2, "hy2://") {
		return nil, fmt.Errorf("[AccessKey] Hysteria2 must start with hysteria2:// or hy2://")
	}
	if c.Access.SSH != "" && !strings.HasPrefix(c.Access.SSH, "ssh://") {
		return nil, fmt.Errorf("[AccessKey] SSH must start with ssh://")
	}
	if c.Access.TUIC != "" && !strings.HasPrefix(c.Access.TUIC, "tuic://") {
		return nil, fmt.Errorf("[AccessKey] TUIC must start with tuic://")
	}
	sources := 0
	if c.Access.SS != "" {
		sources++
	}
	if c.Access.SSConf != "" {
		sources++
	}
	if c.Access.SOCKS5 != "" {
		sources++
	}
	if c.Access.VLESS != "" {
		sources++
	}
	if c.Access.VMess != "" {
		sources++
	}
	if c.Access.Trojan != "" {
		sources++
	}
	if c.Access.Hysteria2 != "" {
		sources++
	}
	if c.Access.SSH != "" {
		sources++
	}
	if c.Access.TUIC != "" {
		sources++
	}
	if c.Access.Key != "" {
		sources++
	}
	if c.Access.KeyFile != "" {
		if path == "" {
			return nil, fmt.Errorf("in-memory configuration requires an inline key source")
		}
		sources++
	}
	if c.Access.Parameters != nil || c.Access.VLESSParameters != nil || c.Access.Type != "" || c.Access.Username != "" || c.Access.ServerName != "" {
		if c.Access.xhttpExtraUsed && c.Access.xhttpFieldsUsed {
			return nil, fmt.Errorf("[AccessKey] XHTTPExtra cannot be combined with separate XHTTP options")
		}
		sources++
	}
	if sources != 1 {
		return nil, fmt.Errorf("[AccessKey] must specify exactly one source: File, SS, SSConf, SOCKS5, VLESS, VMess, Trojan, Hysteria2, SSH, TUIC, Key, or explicit parameters")
	}
	if c.Access.IdentityFile != "" || c.Access.KnownHostsFile != "" {
		if c.Access.Type != "ssh" && c.Access.SSH == "" && c.Access.KeyFile == "" && !strings.HasPrefix(c.Access.Key, "ssh://") {
			return nil, fmt.Errorf("[AccessKey] SSH file options require an SSH profile")
		}
	}
	if c.Access.Parameters != nil || c.Access.VLESSParameters != nil || c.Access.Type != "" || c.Access.Username != "" || c.Access.ServerName != "" {
		if c.Access.Type == "" {
			return nil, fmt.Errorf("[AccessKey] Type is required when using explicit parameters")
		}
		if c.Access.Parameters == nil {
			return nil, fmt.Errorf("[AccessKey] Server and Port are required")
		}
		s := c.Access.Parameters
		if c.Access.Type == "ssh" {
			if c.Tunnel.Mode != "proxy" {
				return nil, fmt.Errorf("SSH requires Mode = proxy")
			}
			if c.Access.Username == "" || s.Server == "" || s.Port < 1 || s.Port > 65535 || s.Method != "" || s.Password != "" || s.Prefix != "" || c.Access.VLESSParameters != nil || c.Access.ServerName != "" {
				return nil, fmt.Errorf("[AccessKey] invalid SSH parameters")
			}
			c.profile = &accesskey.Profile{Name: c.Name, Type: "ssh", TCP: accesskey.Endpoint{Host: s.Server, Port: s.Port}, SSH: accesskey.SSH{User: c.Access.Username, IdentityFile: resolveSSHPath(c.Access.IdentityFile), KnownHostsFile: resolveSSHPath(c.Access.KnownHostsFile)}}
			return c, nil
		}
		if c.Access.Type == "trojan" {
			if c.Access.Username != "" || s.Method != "" || s.Prefix != "" || c.Access.VLESSParameters != nil || s.Password == "" {
				return nil, fmt.Errorf("[AccessKey] invalid Trojan parameters")
			}
			name := c.Access.ServerName
			if name == "" {
				name = s.Server
			}
			t := accesskey.Trojan{Password: s.Password, ServerName: name}
			if err := t.Validate(s.Server, s.Port); err != nil {
				return nil, err
			}
			e := accesskey.Endpoint{Host: s.Server, Port: s.Port}
			c.profile = &accesskey.Profile{Name: c.Name, Type: "trojan", TCP: e, UDP: e, Trojan: t}
			return c, nil
		}
		if c.Access.Type == "vless" {
			if c.Access.Username != "" || s.Method != "" || s.Password != "" || s.Prefix != "" || c.Access.VLESSParameters == nil {
				return nil, fmt.Errorf("[AccessKey] invalid VLESS parameters")
			}
			v := *c.Access.VLESSParameters
			v.ServerName = c.Access.ServerName
			if err := v.Validate(s.Server, s.Port); err != nil {
				return nil, err
			}
			e := accesskey.Endpoint{Host: s.Server, Port: s.Port}
			c.profile = &accesskey.Profile{Name: c.Name, Type: "vless", TCP: e, UDP: e, VLESS: v}
			return c, nil
		}
		if c.Access.VLESSParameters != nil {
			return nil, fmt.Errorf("[AccessKey] VLESS options require Type = vless")
		}
		if c.Access.ServerName != "" {
			return nil, fmt.Errorf("[AccessKey] ServerName requires Type = vless or trojan")
		}
		if c.Access.Type == "socks5" {
			if s.Method != "" || s.Prefix != "" {
				return nil, fmt.Errorf("[AccessKey] Method and Prefix are only valid for shadowsocks")
			}
			if (c.Access.Username == "") != (s.Password == "") {
				return nil, fmt.Errorf("[AccessKey] SOCKS5 Username and Password must both be set")
			}
			if len(c.Access.Username) > 255 || len(s.Password) > 255 {
				return nil, fmt.Errorf("[AccessKey] SOCKS5 credentials are too long")
			}
			p, err := accesskey.ParseSOCKS5("socks5://" + net.JoinHostPort(s.Server, strconv.Itoa(s.Port)))
			if err != nil {
				return nil, err
			}
			p.Username, p.TCP.Secret, p.UDP.Secret = c.Access.Username, s.Password, s.Password
			c.profile = &p
			return c, nil
		}
		if c.Access.Type != "shadowsocks" && c.Access.Type != "ss" {
			return nil, fmt.Errorf("[AccessKey] unsupported Type")
		}
		if c.Access.Username != "" {
			return nil, fmt.Errorf("[AccessKey] Username is only valid for socks5")
		}
		e := accesskey.Endpoint{Host: s.Server, Port: s.Port, Cipher: s.Method, Secret: s.Password, Prefix: s.Prefix}
		if err := e.Validate(); err != nil {
			return nil, err
		}
		c.profile = &accesskey.Profile{Name: c.Name, TCP: e, UDP: e}
		return c, nil
	}
	key := c.Access.Key
	if c.Access.SS != "" {
		key = c.Access.SS
	}
	if c.Access.SSConf != "" {
		key = c.Access.SSConf
	}
	if c.Access.SOCKS5 != "" {
		key = c.Access.SOCKS5
	}
	if c.Access.VLESS != "" {
		key = c.Access.VLESS
	}
	if c.Access.VMess != "" {
		key = c.Access.VMess
	}
	if c.Access.Trojan != "" {
		key = c.Access.Trojan
	}
	if c.Access.Hysteria2 != "" {
		key = c.Access.Hysteria2
	}
	if c.Access.SSH != "" {
		key = c.Access.SSH
	}
	if c.Access.TUIC != "" {
		key = c.Access.TUIC
	}
	if c.Access.KeyFile != "" {
		keyPath := c.Access.KeyFile
		if !filepath.IsAbs(keyPath) {
			keyPath = filepath.Join(filepath.Dir(path), keyPath)
		}
		b, err := readFile(keyPath)
		if err != nil {
			return nil, err
		}
		key = string(b)
	}
	c.key = strings.TrimSpace(strings.TrimPrefix(key, "\ufeff"))
	if strings.HasPrefix(c.key, "ss://") {
		p, err := accesskey.ParseSS(c.key)
		if err != nil {
			return nil, err
		}
		c.profile = &p
		return c, nil
	}
	if strings.HasPrefix(c.key, "socks5://") {
		p, err := accesskey.ParseSOCKS5(c.key)
		if err != nil {
			return nil, err
		}
		c.profile = &p
		return c, nil
	}
	if strings.HasPrefix(c.key, "vless://") {
		p, err := accesskey.ParseVLESS(c.key)
		if err != nil {
			return nil, err
		}
		c.profile = &p
		return c, nil
	}
	if strings.HasPrefix(c.key, "vmess://") {
		p, err := accesskey.ParseVMess(c.key)
		if err != nil {
			return nil, err
		}
		c.profile = &p
		return c, nil
	}
	if strings.HasPrefix(c.key, "trojan://") {
		p, err := accesskey.ParseTrojan(c.key)
		if err != nil {
			return nil, err
		}
		c.profile = &p
		return c, nil
	}
	if strings.HasPrefix(c.key, "hysteria2://") || strings.HasPrefix(c.key, "hy2://") {
		p, err := accesskey.ParseHysteria2(c.key)
		if err != nil {
			return nil, err
		}
		c.profile = &p
		return c, nil
	}
	if strings.HasPrefix(c.key, "ssh://") {
		if c.Tunnel.Mode != "proxy" {
			return nil, fmt.Errorf("SSH requires Mode = proxy")
		}
		p, err := accesskey.ParseSSH(c.key)
		if err != nil {
			return nil, err
		}
		if c.Access.IdentityFile != "" {
			p.SSH.IdentityFile = c.Access.IdentityFile
		}
		if c.Access.KnownHostsFile != "" {
			p.SSH.KnownHostsFile = c.Access.KnownHostsFile
		}
		p.SSH.IdentityFile = resolveSSHPath(p.SSH.IdentityFile)
		p.SSH.KnownHostsFile = resolveSSHPath(p.SSH.KnownHostsFile)
		c.profile = &p
		return c, nil
	}
	if strings.HasPrefix(c.key, "tuic://") {
		p, err := accesskey.ParseTUIC(c.key)
		if err != nil {
			return nil, err
		}
		c.profile = &p
		return c, nil
	}
	if !strings.HasPrefix(c.key, "ssconf://") {
		return nil, fmt.Errorf("access key must start with ss://, ssconf://, socks5://, vless://, vmess://, trojan://, hysteria2://, hy2://, ssh://, or tuic://")
	}
	u, err := url.Parse("https://" + strings.TrimPrefix(c.key, "ssconf://"))
	if err != nil || u.Hostname() == "" || u.User != nil {
		return nil, fmt.Errorf("invalid ssconf URL")
	}
	if u.Port() != "" {
		addr, err := netip.ParseAddrPort(net.JoinHostPort("127.0.0.1", u.Port()))
		if err != nil || addr.Port() == 0 {
			return nil, fmt.Errorf("invalid ssconf port")
		}
	}
	return c, nil
}
func (c *File) Resolve(ctx context.Context) (accesskey.Profile, error) {
	if c.profile != nil {
		return *c.profile, nil
	}
	return accesskey.NewResolver().Resolve(ctx, c.key)
}
func (c *File) ResolveWithTransport(ctx context.Context, t http.RoundTripper) (accesskey.Profile, error) {
	if c.profile != nil {
		return *c.profile, nil
	}
	return accesskey.NewResolverWithTransport(t).Resolve(ctx, c.key)
}
func (c *File) VPNPolicy() (*routing.Policy, error) {
	return routing.Compile(c.Routing)
}
