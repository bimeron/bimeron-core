// Package config defines Bimeron's versioned, WireGuard-style .conf format.
package config

import (
	"bimeron/internal/geofile"
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
	"bimeron/internal/problem"
	"bimeron/internal/routing"
	"bimeron/internal/systemvpn"
)

const maxSize = 64 * 1024

type File struct {
	Version          int
	Name             string
	Access           Access
	Tunnel           Tunnel
	Routing          routing.Config
	GeoData          GeoData
	geoData          *routing.GeoData
	IKEv2            *systemvpn.Config
	interfaceOptions bool
	key              string
	profile          *accesskey.Profile
	ShadowTLS        *accesskey.ShadowTLS
	// lines maps "Section", "Section.Field", "Rule<n>" and "Rule<n>.Field" to
	// one-based profile lines for problem locations.
	lines map[string]int
}
type GeoData struct {
	GeoIPFile   string
	GeoSiteFile string
}

type Access struct {
	SS                string
	SSConf            string
	SOCKS5            string
	HTTP              string
	MASQUE            string
	MASQUEPath        string
	CAFile            string
	VLESS             string
	VMess             string
	Trojan            string
	Naive             string
	Hysteria2         string
	AnyTLS            string
	SSH               string
	TUIC              string
	Key               string
	KeyFile           string
	Type              string
	Parameters        *Parameters
	Username          string
	IdentityFile      string
	KnownHostsFile    string
	VLESSParameters   *accesskey.VLESS
	ServerName        string
	Plugin            string
	PluginOpts        string
	xhttpExtraUsed    bool
	xhttpFieldsUsed   bool
	trojanUnsupported bool
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
		return nil, problem.New("file_unreadable", "could not read configuration or key file")
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxSize+1))
	if err != nil || len(b) > maxSize {
		return nil, problem.New("file_too_large", "configuration or key file exceeds size limit or cannot be read").Arg("limit", "64 KiB")
	}
	return b, nil
}
func parse(b []byte) (*File, error) {
	if !utf8.Valid(b) {
		return nil, problem.New("file_not_utf8", "config must be UTF-8")
	}
	c := &File{Tunnel: Tunnel{Mode: "vpn", IPv6: "enable", Name: "Bimeron", MTU: 1420, DNS: "1.1.1.1", Listen: "127.0.0.1:1080"}, Routing: routing.Config{Default: routing.Proxy}, lines: map[string]int{}}
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
		syntax := func() error {
			return problem.New("syntax_invalid", fmt.Sprintf("invalid configuration at line %d", line)).AtLine(line)
		}
		if strings.HasPrefix(text, "[") {
			if !strings.HasSuffix(text, "]") {
				return nil, syntax()
			}
			section = strings.TrimSpace(text[1 : len(text)-1])
			switch section {
			case "Profile", "AccessKey", "Interface", "Routing", "IKEv2", "ShadowTLS", "GeoData":
				if sections[section] {
					return nil, problem.New("section_duplicate", fmt.Sprintf("duplicate section at line %d", line)).In(section).AtLine(line)
				}
				sections[section] = true
				if section == "IKEv2" {
					c.IKEv2 = &systemvpn.Config{}
				}
				if section == "ShadowTLS" {
					c.ShadowTLS = &accesskey.ShadowTLS{}
				}
			case "Rule":
				c.Routing.Rules = append(c.Routing.Rules, routing.Rule{})
			default:
				return nil, problem.New("section_unknown", fmt.Sprintf("unknown section at line %d", line)).AtLine(line)
			}
			fields = map[string]bool{}
			c.lines[c.lineKey(section, "")] = line
			continue
		}
		key, value, ok := strings.Cut(text, "=")
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if !ok || section == "" || key == "" {
			return nil, syntax()
		}
		if fields[key] {
			return nil, c.inRule(problem.New("option_duplicate", fmt.Sprintf("duplicate option at line %d", line)).In(section).At(key).AtLine(line), section)
		}
		fields[key] = true
		c.lines[c.lineKey(section, key)] = line
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
			return nil, c.inRule(problem.New("value_required", fmt.Sprintf("invalid configuration at line %d", line)).In(section).On(key, "").AtLine(line), section)
		}
		number := func() (int, error) {
			n, err := strconv.Atoi(value)
			if err != nil {
				return 0, problem.New("number_invalid", fmt.Sprintf("invalid number at line %d", line)).In(section).At(key).AtLine(line)
			}
			return n, nil
		}
		recognized := true
		var err error
		switch section {
		case "ShadowTLS":
			switch key {
			case "ServerName":
				c.ShadowTLS.ServerName = value
			case "Password":
				c.ShadowTLS.Password = value
			default:
				recognized = false
			}
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
			if key != "Mode" {
				c.interfaceOptions = true
			}
			switch key {
			case "KillSwitch":
				if value != "true" && value != "false" {
					return nil, problem.New("boolean_invalid", "[Interface] KillSwitch must be true or false").In(section).At(key).AtLine(line)
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
		case "IKEv2":
			switch key {
			case "WindowsProfile":
				c.IKEv2.WindowsProfile = value
			case "ServerName":
				c.IKEv2.ServerName = value
			case "KillSwitch":
				if value != "true" && value != "false" {
					return nil, problem.New("boolean_invalid", "IKEv2 KillSwitch must be true or false").In(section).At(key).AtLine(line)
				}
				c.IKEv2.KillSwitch = value == "true"
			default:
				recognized = false
			}
		case "AccessKey":
			switch key {
			case "Plugin":
				c.Access.Plugin = value
			case "PluginOpts":
				c.Access.PluginOpts = value
			case "VLESS":
				c.Access.VLESS = value
			case "VMess":
				c.Access.VMess = value
			case "Trojan":
				c.Access.Trojan = value
			case "Naive":
				c.Access.Naive = value
			case "Hysteria2":
				c.Access.Hysteria2 = value
			case "AnyTLS":
				c.Access.AnyTLS = value
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
			case "HTTP":
				c.Access.HTTP = value
			case "MASQUE":
				c.Access.MASQUE = value
			case "MASQUEPath":
				c.Access.MASQUEPath = value
			case "CAFile":
				c.Access.CAFile = value
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
				switch key {
				case "Network", "Security", "ALPN", "WSPath", "WSHost", "GRPCServiceName", "GRPCAuthority", "GRPCMultiMode":
				default:
					c.Access.trojanUnsupported = true
				}
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
						return nil, problem.New("boolean_invalid", "[AccessKey] GRPCMultiMode must be true or false").In(section).At(key).AtLine(line)
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
		case "GeoData":
			switch key {
			case "GeoIPFile":
				c.GeoData.GeoIPFile = value
			case "GeoSiteFile":
				c.GeoData.GeoSiteFile = value
			default:
				recognized = false
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
			case "GeoIP":
				r.GeoIP = value
			case "GeoSite":
				r.GeoSite = value
			case "Action":
				r.Action = routing.Action(value)
			default:
				recognized = false
			}
		}
		if err != nil {
			p := problem.Of(err)
			if p.Section == "" {
				p.In(section)
			}
			if p.Field == "" {
				p.At(key)
			}
			return nil, c.inRule(p.AtLine(line), section)
		}
		if !recognized {
			return nil, c.inRule(problem.New("option_unknown", fmt.Sprintf("unknown option at line %d", line)).In(section).AtLine(line), section)
		}
	}
	if scanner.Err() != nil {
		return nil, problem.New("syntax_invalid", "could not parse config")
	}
	return c, nil
}

// vlessFields lists the explicit VLESS transport options; "XHTTP*" matches any
// separate XHTTP option.
var vlessFields = []string{"ID", "Encryption", "Flow", "Network", "Security", "PublicKey", "ShortID", "Fingerprint", "SpiderX", "ALPN", "WSPath", "WSHost", "WSEarlyData", "GRPCServiceName", "GRPCAuthority", "GRPCMultiMode", "XHTTPPath", "XHTTPHost", "XHTTPMode", "XHTTPExtra", "XHTTP*"}

// present returns the first listed [AccessKey] option that the profile sets.
func (c *File) present(fields ...string) string {
	for _, field := range fields {
		if field == "XHTTP*" {
			best, line := "", 0
			for key, l := range c.lines {
				if name, ok := strings.CutPrefix(key, "AccessKey.XHTTP"); ok && name != "" && (line == 0 || l < line) {
					best, line = "XHTTP"+name, l
				}
			}
			if best != "" {
				return best
			}
			continue
		}
		if c.lines["AccessKey."+field] > 0 {
			return field
		}
	}
	return ""
}

// unsupported reports the first set option that typ does not use.
func (c *File) unsupported(typ, message string, fields ...string) *problem.Error {
	field := c.present(fields...)
	p := problem.New("option_not_supported", message).In("AccessKey").At(field).Arg("type", typ)
	if field == "Password" {
		p.On(field, "set")
	}
	return p
}

func credentialsIncomplete(message, username string) *problem.Error {
	p := problem.New("credentials_incomplete", message).In("AccessKey")
	if username == "" {
		return p.On("Username", "").Also("Password")
	}
	return p.On("Password", "").Also("Username")
}

// lineKey names a section or field in File.lines. Rule sections are numbered.
func (c *File) lineKey(section, field string) string {
	if section == "Rule" {
		section += strconv.Itoa(len(c.Routing.Rules))
	}
	if field == "" {
		return section
	}
	return section + "." + field
}

func (c *File) inRule(p *problem.Error, section string) *problem.Error {
	if section == "Rule" && p.Rule == 0 {
		p.AtRule(len(c.Routing.Rules))
	}
	return p
}

// accessSource returns the [AccessKey] option holding a URI or key, or "" for
// explicit parameters.
func (a Access) accessSource() string {
	for _, s := range []struct{ name, value string }{
		{"SS", a.SS}, {"SSConf", a.SSConf}, {"SOCKS5", a.SOCKS5}, {"HTTP", a.HTTP}, {"MASQUE", a.MASQUE},
		{"VLESS", a.VLESS}, {"VMess", a.VMess}, {"Trojan", a.Trojan}, {"Naive", a.Naive},
		{"Hysteria2", a.Hysteria2}, {"AnyTLS", a.AnyTLS}, {"SSH", a.SSH}, {"TUIC", a.TUIC},
		{"Key", a.Key}, {"File", a.KeyFile},
	} {
		if s.value != "" {
			return s.name
		}
	}
	return ""
}

// keyProblem locates a failure of a URI or key parser in [AccessKey].
func (c *File) keyProblem(err error) error {
	p := problem.Of(err)
	p.In("AccessKey")
	if p.Source == "" {
		p.From(c.Access.accessSource())
	}
	return p
}

// accessProblem locates a failure of explicit [AccessKey] parameters.
func accessProblem(err error) error {
	p := problem.Of(err)
	if p.Section == "" {
		p.In("AccessKey")
	}
	return p
}

// locate fills the profile line of a problem from recorded field positions.
func (c *File) locate(err error) error {
	p := problem.Of(err)
	if p.Line != 0 || c == nil {
		return p
	}
	section := p.Section
	if p.Rule > 0 {
		section = "Rule" + strconv.Itoa(p.Rule)
	}
	for _, key := range []string{
		func() string {
			if p.Source != "" {
				return "AccessKey." + p.Source
			}
			return ""
		}(),
		func() string {
			if p.Field != "" {
				return section + "." + p.Field
			}
			return ""
		}(),
		section,
	} {
		if line := c.lines[key]; key != "" && line > 0 {
			return p.AtLine(line)
		}
	}
	return p
}

func Load(path string) (*File, error) {
	b, err := readFile(path)
	if err != nil {
		return nil, err
	}
	return loadBytes(b, path, nil, nil)
}

// ParseData loads an in-memory configuration for sandboxed embedding. File
// sources must be expanded by the host before crossing the process boundary.
func ParseData(b []byte) (*File, error) {
	if len(b) > maxSize {
		return nil, problem.New("file_too_large", "configuration exceeds size limit").Arg("limit", "64 KiB")
	}
	return loadBytes(b, "", nil, nil)
}

// ParseDataWithGeoData accepts explicit resource bytes and never reads files.
func ParseDataWithGeoData(b, geoIP, geoSite []byte) (*File, error) {
	if len(b) > maxSize {
		return nil, problem.New("file_too_large", "configuration exceeds size limit").Arg("limit", "64 KiB")
	}
	return loadBytes(b, "", geoIP, geoSite)
}
func loadBytes(b []byte, path string, geoIP, geoSite []byte) (*File, error) {
	c, err := parse(b)
	if err != nil {
		return nil, err
	}
	if _, err := loadBaseBytes(c, path, geoIP, geoSite); err != nil {
		return nil, c.locate(err)
	}
	if c.ShadowTLS != nil {
		if err := c.ShadowTLS.Validate(); err != nil {
			return nil, c.locate(shadowTLSProblem(err))
		}
		if c.profile != nil {
			p, err := c.withShadowTLS(*c.profile, nil)
			if err != nil {
				return nil, c.locate(wrappedProblem(err))
			}
			c.profile = &p
		}
	}
	return c, nil
}

// shadowTLSProblem places wrapper failures without a section in [ShadowTLS].
func shadowTLSProblem(err error) error {
	p := problem.Of(err)
	if p.Section == "" {
		p.In("ShadowTLS")
	}
	return p
}

// wrappedProblem places failures of the access key combined with ShadowTLS:
// inner protocol fields stay in [AccessKey], wrapper-level failures without a
// field belong to [ShadowTLS].
func wrappedProblem(err error) error {
	p := problem.Of(err)
	if p.Section == "" && p.Field != "" {
		p.In("AccessKey")
	}
	return shadowTLSProblem(p)
}

func loadBaseBytes(c *File, path string, geoIP, geoSite []byte) (*File, error) {
	var err error
	if c.Version != 1 {
		return nil, problem.New("profile_version_unsupported", "[Profile] Version must be 1").In("Profile").At("Version").Arg("version", "1")
	}
	if c.IKEv2 != nil {
		if err := c.IKEv2.Validate(); err != nil {
			p := problem.Of(err)
			if p.Section == "" {
				p.In("IKEv2")
			}
			return nil, p
		}
		if c.ShadowTLS != nil || c.Access != (Access{}) || c.Tunnel.Mode != "vpn" || c.interfaceOptions || c.Routing.Default != routing.Proxy || len(c.Routing.Rules) != 0 {
			return nil, problem.New("ikev2_exclusive", "IKEv2 requires VPN mode without AccessKey, interface overrides or routing rules").In("IKEv2")
		}
		// Do not inherit packet-backend defaults into an OS-managed tunnel.
		c.Tunnel = Tunnel{Mode: "vpn", IPv6: "system"}
		return c, nil
	}
	resolveSSHPath := func(value string) string {
		if value != "" && path != "" && !filepath.IsAbs(value) && value != "~" && !strings.HasPrefix(value, "~/") && !strings.HasPrefix(value, `~\`) {
			return filepath.Join(filepath.Dir(path), value)
		}
		return value
	}
	if c.Tunnel.Mode != "vpn" && c.Tunnel.Mode != "proxy" {
		return nil, problem.New("choice_invalid", "[Interface] Mode must be vpn or proxy").In("Interface").At("Mode").Arg("allowed", "vpn, proxy")
	}
	if c.Tunnel.KillSwitch && c.Tunnel.Mode != "vpn" {
		return nil, problem.New("kill_switch_requires_vpn", "KillSwitch requires Mode = vpn").In("Interface").At("KillSwitch").Also("Mode")
	}
	if c.Tunnel.IPv6 != "enable" && c.Tunnel.IPv6 != "disable" {
		return nil, problem.New("choice_invalid", "[Interface] IPv6 must be enable or disable").In("Interface").At("IPv6").Arg("allowed", "enable, disable")
	}
	if c.Tunnel.Mode == "proxy" && c.Tunnel.IPv6 == "disable" {
		return nil, problem.New("ipv6_disable_requires_vpn", "[Interface] IPv6 = disable requires Mode = vpn").In("Interface").At("IPv6").Also("Mode")
	}
	if !interfaceName.MatchString(c.Tunnel.Name) {
		return nil, problem.New("interface_name_invalid", "[Interface] Name must start with a letter and contain 1-32 ASCII letters, digits, underscores or hyphens").In("Interface").On("Name", c.Tunnel.Name).Arg("max", "32")
	}
	if c.Tunnel.MTU < 1280 || c.Tunnel.MTU > 1500 {
		return nil, problem.New("number_out_of_range", "[Interface] MTU must be between 1280 and 1500").In("Interface").At("MTU").Arg("min", "1280").Arg("max", "1500")
	}
	if _, err := dnsconfig.Parse(c.Tunnel.DNS); err != nil {
		return nil, problem.Of(err).In("Interface").At("DNS")
	}
	address, err := netip.ParseAddrPort(c.Tunnel.Listen)
	if err != nil || !address.Addr().IsLoopback() || address.Port() == 0 {
		return nil, problem.New("listen_invalid", "[Interface] Listen must be a loopback IP and port").In("Interface").At("Listen")
	}
	if c.Tunnel.KillSwitch {
		for i, r := range c.Routing.Rules {
			if r.Domain != "" || r.GeoIP != "" || r.GeoSite != "" {
				field := "Domain"
				if r.GeoIP != "" {
					field = "GeoIP"
				} else if r.GeoSite != "" {
					field = "GeoSite"
				}
				return nil, problem.New("kill_switch_cidr_only", fmt.Sprintf("rule %d: kill switch supports CIDR rules only", i+1)).In("Rule").At(field).AtRule(i + 1)
			}
		}
	}
	if path != "" {
		needIP, needSite := false, false
		for _, r := range c.Routing.Rules {
			needIP = needIP || r.GeoIP != ""
			needSite = needSite || r.GeoSite != ""
		}
		if needIP {
			geoIP, err = readGeoData(path, c.GeoData.GeoIPFile, "geoip")
			if err != nil {
				return nil, err
			}
		}
		if needSite {
			geoSite, err = readGeoData(path, c.GeoData.GeoSiteFile, "geosite")
			if err != nil {
				return nil, err
			}
		}
	}
	c.geoData, err = routing.DecodeGeoData(geoIP, geoSite)
	if err != nil {
		return nil, err
	}
	if _, err := c.RoutingPolicy(); err != nil {
		return nil, err
	}
	if c.Tunnel.Mode == "vpn" {
		if _, err := c.VPNPolicy(); err != nil {
			return nil, err
		}
	}
	if c.Access.SS != "" && !strings.HasPrefix(c.Access.SS, "ss://") {
		return nil, problem.New("uri_scheme_invalid", "[AccessKey] SS must start with ss://").In("AccessKey").From("SS").Arg("schemes", "ss://")
	}
	if c.Access.SSConf != "" && !strings.HasPrefix(c.Access.SSConf, "ssconf://") {
		return nil, problem.New("uri_scheme_invalid", "[AccessKey] SSConf must start with ssconf://").In("AccessKey").From("SSConf").Arg("schemes", "ssconf://")
	}
	if c.Access.SOCKS5 != "" && !strings.HasPrefix(c.Access.SOCKS5, "socks5://") {
		return nil, problem.New("uri_scheme_invalid", "[AccessKey] SOCKS5 must start with socks5://").In("AccessKey").From("SOCKS5").Arg("schemes", "socks5://")
	}
	if c.Access.HTTP != "" && !(strings.HasPrefix(c.Access.HTTP, "http://") || strings.HasPrefix(c.Access.HTTP, "https://")) {
		return nil, problem.New("uri_scheme_invalid", "[AccessKey] HTTP must start with http:// or https://").In("AccessKey").From("HTTP").Arg("schemes", "http:// or https://")
	}
	if c.Access.VLESS != "" && !strings.HasPrefix(c.Access.VLESS, "vless://") {
		return nil, problem.New("uri_scheme_invalid", "[AccessKey] VLESS must start with vless://").In("AccessKey").From("VLESS").Arg("schemes", "vless://")
	}
	if c.Access.VMess != "" && !strings.HasPrefix(c.Access.VMess, "vmess://") {
		return nil, problem.New("uri_scheme_invalid", "[AccessKey] VMess must start with vmess://").In("AccessKey").From("VMess").Arg("schemes", "vmess://")
	}
	if c.Access.Trojan != "" && !strings.HasPrefix(c.Access.Trojan, "trojan://") {
		return nil, problem.New("uri_scheme_invalid", "[AccessKey] Trojan must start with trojan://").In("AccessKey").From("Trojan").Arg("schemes", "trojan://")
	}
	if c.Access.Naive != "" && !strings.HasPrefix(c.Access.Naive, "naive+https://") && !strings.HasPrefix(c.Access.Naive, "naive+quic://") {
		return nil, problem.New("uri_scheme_invalid", "[AccessKey] Naive must start with naive+https:// or naive+quic://").In("AccessKey").From("Naive").Arg("schemes", "naive+https:// or naive+quic://")
	}
	if c.Access.Hysteria2 != "" && !strings.HasPrefix(c.Access.Hysteria2, "hysteria2://") && !strings.HasPrefix(c.Access.Hysteria2, "hy2://") {
		return nil, problem.New("uri_scheme_invalid", "[AccessKey] Hysteria2 must start with hysteria2:// or hy2://").In("AccessKey").From("Hysteria2").Arg("schemes", "hysteria2:// or hy2://")
	}
	if c.Access.AnyTLS != "" && !strings.HasPrefix(c.Access.AnyTLS, "anytls://") {
		return nil, problem.New("uri_scheme_invalid", "[AccessKey] AnyTLS must start with anytls://").In("AccessKey").From("AnyTLS").Arg("schemes", "anytls://")
	}
	if c.Access.SSH != "" && !strings.HasPrefix(c.Access.SSH, "ssh://") {
		return nil, problem.New("uri_scheme_invalid", "[AccessKey] SSH must start with ssh://").In("AccessKey").From("SSH").Arg("schemes", "ssh://")
	}
	if c.Access.TUIC != "" && !strings.HasPrefix(c.Access.TUIC, "tuic://") {
		return nil, problem.New("uri_scheme_invalid", "[AccessKey] TUIC must start with tuic://").In("AccessKey").From("TUIC").Arg("schemes", "tuic://")
	}
	if c.Access.MASQUE != "" && !strings.HasPrefix(c.Access.MASQUE, "masque://") {
		return nil, problem.New("uri_scheme_invalid", "[AccessKey] MASQUE must start with masque://").In("AccessKey").From("MASQUE").Arg("schemes", "masque://")
	}
	if c.Access.Type != "masque" && (c.Access.MASQUEPath != "" || c.Access.CAFile != "") {
		return nil, problem.New("option_requires_type", "[AccessKey] MASQUEPath and CAFile require Type = masque").In("AccessKey").At(c.present("MASQUEPath", "CAFile")).Arg("type", "MASQUE")
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
	if c.Access.HTTP != "" {
		sources++
	}
	if c.Access.MASQUE != "" {
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
	if c.Access.Naive != "" {
		sources++
	}
	if c.Access.Hysteria2 != "" {
		sources++
	}
	if c.Access.AnyTLS != "" {
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
			return nil, problem.New("key_file_unavailable", "in-memory configuration requires an inline key source").In("AccessKey").At("File")
		}
		sources++
	}
	if c.Access.Plugin != "" || c.Access.PluginOpts != "" {
		if c.Access.Type != "shadowsocks" && c.Access.Type != "ss" {
			return nil, problem.New("option_requires_type", "[AccessKey] plugin options require explicit Shadowsocks parameters").In("AccessKey").At(c.present("Plugin", "PluginOpts")).Arg("type", "Shadowsocks")
		}
	}
	if c.Access.Parameters != nil || c.Access.VLESSParameters != nil || c.Access.Type != "" || c.Access.Username != "" || c.Access.ServerName != "" || c.Access.Plugin != "" || c.Access.PluginOpts != "" {
		if c.Access.xhttpExtraUsed && c.Access.xhttpFieldsUsed {
			return nil, problem.New("xhttp_extra_conflict", "[AccessKey] XHTTPExtra cannot be combined with separate XHTTP options").In("AccessKey").At("XHTTPExtra")
		}
		sources++
	}
	if sources != 1 {
		code := "access_key_missing"
		if sources > 1 {
			code = "access_key_multiple_sources"
		}
		return nil, problem.New(code, "[AccessKey] must specify exactly one source: File, SS, SSConf, SOCKS5, HTTP, MASQUE, VLESS, VMess, Trojan, Naive, Hysteria2, AnyTLS, SSH, TUIC, Key, or explicit parameters").In("AccessKey")
	}
	if c.Access.IdentityFile != "" || c.Access.KnownHostsFile != "" {
		if c.Access.Type != "ssh" && c.Access.SSH == "" && c.Access.KeyFile == "" && !strings.HasPrefix(c.Access.Key, "ssh://") {
			return nil, problem.New("option_requires_type", "[AccessKey] SSH file options require an SSH profile").In("AccessKey").At(c.present("IdentityFile", "KnownHostsFile")).Arg("type", "SSH")
		}
	}
	if c.Access.Parameters != nil || c.Access.VLESSParameters != nil || c.Access.Type != "" || c.Access.Username != "" || c.Access.ServerName != "" {
		if c.Access.Type == "" {
			return nil, problem.New("value_required", "[AccessKey] Type is required when using explicit parameters").In("AccessKey").On("Type", "")
		}
		if c.Access.Parameters == nil {
			return nil, problem.New("value_required", "[AccessKey] Server and Port are required").In("AccessKey").On("Server", "").Also("Port")
		}
		s := c.Access.Parameters
		if c.Access.Type == "masque" {
			if s.Method != "" || s.Prefix != "" || c.Access.VLESSParameters != nil {
				return nil, c.unsupported("MASQUE", "[AccessKey] invalid MASQUE parameters", append([]string{"Method", "Prefix"}, vlessFields...)...)
			}
			m := accesskey.MASQUE{ProxyHost: s.Server, ServerName: c.Access.ServerName, UDPPath: c.Access.MASQUEPath, CAFile: c.Access.CAFile}
			if m.ServerName == "" {
				m.ServerName = s.Server
			}
			if m.UDPPath == "" {
				m.UDPPath = accesskey.DefaultMASQUEPath
			}
			if m.CAFile != "" && !filepath.IsAbs(m.CAFile) {
				if path == "" {
					return nil, problem.New("path_must_be_absolute", "in-memory configuration requires an absolute CAFile").In("AccessKey").At("CAFile")
				}
				m.CAFile = filepath.Join(filepath.Dir(path), m.CAFile)
			}
			if err := m.Validate(s.Server, s.Port, c.Access.Username, s.Password); err != nil {
				return nil, accessProblem(err)
			}
			e := accesskey.Endpoint{Host: s.Server, Port: s.Port, Secret: s.Password}
			c.profile = &accesskey.Profile{Name: c.Name, Type: "masque", TCP: e, UDP: e, Username: c.Access.Username, MASQUE: m}
			return c, nil
		}
		if c.Access.Type == "ssh" {
			const message = "[AccessKey] invalid SSH parameters"
			if c.Access.Username == "" {
				return nil, problem.New("value_required", message).In("AccessKey").On("Username", "")
			}
			if s.Server == "" {
				return nil, problem.New("value_required", message).In("AccessKey").On("Server", "")
			}
			if s.Port < 1 || s.Port > 65535 {
				return nil, problem.New("port_invalid", message).In("AccessKey").At("Port")
			}
			if s.Method != "" || s.Password != "" || s.Prefix != "" || c.Access.VLESSParameters != nil || c.Access.ServerName != "" {
				return nil, c.unsupported("SSH", message, append([]string{"Method", "Password", "Prefix", "ServerName"}, vlessFields...)...)
			}
			c.profile = &accesskey.Profile{Name: c.Name, Type: "ssh", TCP: accesskey.Endpoint{Host: s.Server, Port: s.Port}, SSH: accesskey.SSH{User: c.Access.Username, IdentityFile: resolveSSHPath(c.Access.IdentityFile), KnownHostsFile: resolveSSHPath(c.Access.KnownHostsFile)}}
			return c, nil
		}
		if c.Access.Type == "trojan" {
			const message = "[AccessKey] invalid Trojan parameters"
			if s.Password == "" {
				return nil, problem.New("value_required", message).In("AccessKey").On("Password", "")
			}
			if c.Access.Username != "" || s.Method != "" || s.Prefix != "" {
				return nil, c.unsupported("Trojan", message, "Username", "Method", "Prefix")
			}
			name := c.Access.ServerName
			if name == "" {
				name = s.Server
			}
			t := accesskey.Trojan{Password: s.Password, ServerName: name}
			if v := c.Access.VLESSParameters; v != nil {
				if c.Access.trojanUnsupported || v.ID != "" || v.Encryption != "" || v.Flow != "" || v.PublicKey != "" || v.ShortID != "" || v.Fingerprint != "" || v.SpiderX != "" || v.WSEarlyData != 0 || v.XHTTPPath != "" || v.XHTTPHost != "" || v.XHTTPMode != "" || v.XHTTPOptions != nil || (v.Security != "" && v.Security != "tls") {
					if v.Security != "" && v.Security != "tls" && !c.Access.trojanUnsupported {
						return nil, problem.New("choice_invalid", "[AccessKey] unsupported Trojan transport options").In("AccessKey").At("Security").Arg("allowed", "tls")
					}
					return nil, c.unsupported("Trojan", "[AccessKey] unsupported Trojan transport options", "ID", "Encryption", "Flow", "PublicKey", "ShortID", "Fingerprint", "SpiderX", "WSEarlyData", "XHTTPPath", "XHTTPHost", "XHTTPMode", "XHTTPExtra", "XHTTP*")
				}
				t.Network, t.ALPN, t.WSPath, t.WSHost = v.Network, v.ALPN, v.WSPath, v.WSHost
				t.GRPCServiceName, t.GRPCAuthority, t.GRPCMultiMode = v.GRPCServiceName, v.GRPCAuthority, v.GRPCMultiMode
			}
			if err := t.Validate(s.Server, s.Port); err != nil {
				return nil, accessProblem(err)
			}
			e := accesskey.Endpoint{Host: s.Server, Port: s.Port}
			c.profile = &accesskey.Profile{Name: c.Name, Type: "trojan", TCP: e, UDP: e, Trojan: t}
			return c, nil
		}
		if c.Access.Type == "naive" {
			const message = "[AccessKey] invalid NaiveProxy parameters"
			if c.Access.Username == "" {
				return nil, problem.New("value_required", message).In("AccessKey").On("Username", "")
			}
			if s.Password == "" {
				return nil, problem.New("value_required", message).In("AccessKey").On("Password", "")
			}
			if s.Method != "" || s.Prefix != "" || c.Access.VLESSParameters != nil {
				return nil, c.unsupported("NaiveProxy", message, append([]string{"Method", "Prefix"}, vlessFields...)...)
			}
			name := c.Access.ServerName
			if name == "" {
				name = s.Server
			}
			n := accesskey.Naive{User: c.Access.Username, Password: s.Password, ServerName: name}
			if err := n.Validate(s.Server, s.Port); err != nil {
				return nil, accessProblem(err)
			}
			c.profile = &accesskey.Profile{Name: c.Name, Type: "naive", TCP: accesskey.Endpoint{Host: s.Server, Port: s.Port}, Naive: n}
			return c, nil
		}
		if c.Access.Type == "vless" {
			const message = "[AccessKey] invalid VLESS parameters"
			if c.Access.Username != "" || s.Method != "" || s.Password != "" || s.Prefix != "" {
				return nil, c.unsupported("VLESS", message, "Username", "Method", "Password", "Prefix")
			}
			if c.Access.VLESSParameters == nil {
				return nil, problem.New("value_required", message).In("AccessKey").On("ID", "")
			}
			v := *c.Access.VLESSParameters
			v.ServerName = c.Access.ServerName
			if err := v.Validate(s.Server, s.Port); err != nil {
				return nil, accessProblem(err)
			}
			e := accesskey.Endpoint{Host: s.Server, Port: s.Port}
			c.profile = &accesskey.Profile{Name: c.Name, Type: "vless", TCP: e, UDP: e, VLESS: v}
			return c, nil
		}
		if c.Access.VLESSParameters != nil {
			return nil, problem.New("option_requires_type", "[AccessKey] VLESS options require Type = vless").In("AccessKey").At(c.present(vlessFields...)).Arg("type", "VLESS")
		}
		if c.Access.ServerName != "" {
			return nil, problem.New("option_requires_type", "[AccessKey] ServerName requires Type = vless or trojan").In("AccessKey").At("ServerName").Arg("type", "VLESS, Trojan, NaiveProxy, MASQUE")
		}
		if c.Access.Type == "socks5" {
			if s.Method != "" || s.Prefix != "" {
				return nil, c.unsupported("SOCKS5", "[AccessKey] Method and Prefix are only valid for shadowsocks", "Method", "Prefix")
			}
			if (c.Access.Username == "") != (s.Password == "") {
				return nil, credentialsIncomplete("[AccessKey] SOCKS5 Username and Password must both be set", c.Access.Username)
			}
			if len(c.Access.Username) > 255 {
				return nil, problem.New("value_too_long", "[AccessKey] SOCKS5 credentials are too long").In("AccessKey").At("Username").Arg("max", "255")
			}
			if len(s.Password) > 255 {
				return nil, problem.New("value_too_long", "[AccessKey] SOCKS5 credentials are too long").In("AccessKey").On("Password", s.Password).Arg("max", "255")
			}
			p, err := accesskey.ParseSOCKS5("socks5://" + net.JoinHostPort(s.Server, strconv.Itoa(s.Port)))
			if err != nil {
				return nil, accessProblem(err)
			}
			p.Username, p.TCP.Secret, p.UDP.Secret = c.Access.Username, s.Password, s.Password
			c.profile = &p
			return c, nil
		}
		if c.Access.Type == "http" || c.Access.Type == "https" {
			const message = "[AccessKey] invalid HTTP proxy parameters"
			if s.Method != "" || s.Prefix != "" {
				return nil, c.unsupported("HTTP", message, "Method", "Prefix")
			}
			if (c.Access.Username == "") != (s.Password == "") {
				return nil, credentialsIncomplete(message, c.Access.Username)
			}
			if strings.ContainsAny(c.Access.Username, ":\r\n") {
				return nil, problem.New("value_has_invalid_characters", message).In("AccessKey").At("Username")
			}
			if strings.ContainsAny(s.Password, "\r\n") {
				return nil, problem.New("value_has_invalid_characters", message).In("AccessKey").On("Password", s.Password)
			}
			p, err := accesskey.ParseHTTPConnect(c.Access.Type + "://" + net.JoinHostPort(s.Server, strconv.Itoa(s.Port)))
			if err != nil {
				return nil, accessProblem(err)
			}
			p.Username, p.TCP.Secret = c.Access.Username, s.Password
			c.profile = &p
			return c, nil
		}
		if c.Access.Type != "shadowsocks" && c.Access.Type != "ss" {
			return nil, problem.New("choice_invalid", "[AccessKey] unsupported Type").In("AccessKey").At("Type").Arg("allowed", "shadowsocks, socks5, http, https, vless, trojan, naive, ssh, masque")
		}
		if c.Access.Username != "" {
			return nil, problem.New("option_not_supported", "[AccessKey] Username is only valid for socks5, http, or https").In("AccessKey").At("Username").Arg("type", "Shadowsocks")
		}
		e := accesskey.Endpoint{Host: s.Server, Port: s.Port, Cipher: s.Method, Secret: s.Password, Prefix: s.Prefix}
		if err := e.Validate(); err != nil {
			return nil, accessProblem(err)
		}
		c.profile = &accesskey.Profile{Name: c.Name, TCP: e, UDP: e}
		c.profile.SSPlugin, err = accesskey.ParseSSPlugin(c.Access.Plugin, c.Access.PluginOpts)
		if err != nil {
			return nil, accessProblem(err)
		}
		if c.profile.SSPlugin != nil {
			c.profile.UDP = accesskey.Endpoint{}
		}
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
	if c.Access.HTTP != "" {
		key = c.Access.HTTP
	}
	if c.Access.MASQUE != "" {
		key = c.Access.MASQUE
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
	if c.Access.Naive != "" {
		key = c.Access.Naive
	}
	if c.Access.Hysteria2 != "" {
		key = c.Access.Hysteria2
	}
	if c.Access.AnyTLS != "" {
		key = c.Access.AnyTLS
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
			return nil, c.keyProblem(err)
		}
		key = string(b)
	}
	c.key = strings.TrimSpace(strings.TrimPrefix(key, "\ufeff"))
	if strings.HasPrefix(c.key, "ss://") {
		p, err := accesskey.ParseSS(c.key)
		if err != nil {
			return nil, c.keyProblem(err)
		}
		c.profile = &p
		return c, nil
	}
	if strings.HasPrefix(c.key, "socks5://") {
		p, err := accesskey.ParseSOCKS5(c.key)
		if err != nil {
			return nil, c.keyProblem(err)
		}
		c.profile = &p
		return c, nil
	}
	if strings.HasPrefix(c.key, "masque://") {
		p, err := accesskey.ParseMASQUE(c.key)
		if err != nil {
			return nil, c.keyProblem(err)
		}
		c.profile = &p
		return c, nil
	}
	if strings.HasPrefix(c.key, "http://") || strings.HasPrefix(c.key, "https://") {
		p, err := accesskey.ParseHTTPConnect(c.key)
		if err != nil {
			return nil, c.keyProblem(err)
		}
		c.profile = &p
		return c, nil
	}
	if strings.HasPrefix(c.key, "vless://") {
		p, err := accesskey.ParseVLESS(c.key)
		if err != nil {
			return nil, c.keyProblem(err)
		}
		c.profile = &p
		return c, nil
	}
	if strings.HasPrefix(c.key, "vmess://") {
		p, err := accesskey.ParseVMess(c.key)
		if err != nil {
			return nil, c.keyProblem(err)
		}
		c.profile = &p
		return c, nil
	}
	if strings.HasPrefix(c.key, "trojan://") {
		p, err := accesskey.ParseTrojan(c.key)
		if err != nil {
			return nil, c.keyProblem(err)
		}
		c.profile = &p
		return c, nil
	}
	if strings.HasPrefix(c.key, "naive+https://") || strings.HasPrefix(c.key, "naive+quic://") {
		p, err := accesskey.ParseNaive(c.key)
		if err != nil {
			return nil, c.keyProblem(err)
		}
		c.profile = &p
		return c, nil
	}
	if strings.HasPrefix(c.key, "hysteria2://") || strings.HasPrefix(c.key, "hy2://") {
		p, err := accesskey.ParseHysteria2(c.key)
		if err != nil {
			return nil, c.keyProblem(err)
		}
		c.profile = &p
		return c, nil
	}
	if strings.HasPrefix(c.key, "anytls://") {
		p, err := accesskey.ParseAnyTLS(c.key)
		if err != nil {
			return nil, c.keyProblem(err)
		}
		c.profile = &p
		return c, nil
	}
	if strings.HasPrefix(c.key, "ssh://") {
		p, err := accesskey.ParseSSH(c.key)
		if err != nil {
			return nil, c.keyProblem(err)
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
			return nil, c.keyProblem(err)
		}
		c.profile = &p
		return c, nil
	}
	if !strings.HasPrefix(c.key, "ssconf://") {
		return nil, c.keyProblem(problem.New("uri_scheme_invalid", "access key must start with ss://, ssconf://, socks5://, http://, https://, masque://, vless://, vmess://, trojan://, naive+https://, naive+quic://, hysteria2://, hy2://, anytls://, ssh://, or tuic://").Arg("schemes", "ss://, ssconf://, socks5://, http://, https://, masque://, vless://, vmess://, trojan://, naive+https://, naive+quic://, hysteria2://, hy2://, anytls://, ssh://, tuic://"))
	}
	u, err := url.Parse("https://" + strings.TrimPrefix(c.key, "ssconf://"))
	if err != nil || u.Hostname() == "" || u.User != nil {
		return nil, c.keyProblem(problem.New("uri_invalid", "invalid ssconf URL"))
	}
	if u.Port() != "" {
		addr, err := netip.ParseAddrPort(net.JoinHostPort("127.0.0.1", u.Port()))
		if err != nil || addr.Port() == 0 {
			return nil, c.keyProblem(problem.New("port_invalid", "invalid ssconf port").At("Port"))
		}
	}
	return c, nil
}
func (c *File) Resolve(ctx context.Context) (accesskey.Profile, error) {
	if c.IKEv2 != nil {
		return accesskey.Profile{}, fmt.Errorf("IKEv2 uses a system VPN backend, not an upstream dialer")
	}
	if c.profile != nil {
		return c.withShadowTLS(*c.profile, nil)
	}
	return c.withShadowTLS(accesskey.NewResolver().Resolve(ctx, c.key))
}
func (c *File) ResolveWithTransport(ctx context.Context, t http.RoundTripper) (accesskey.Profile, error) {
	if c.IKEv2 != nil {
		return accesskey.Profile{}, fmt.Errorf("IKEv2 uses a system VPN backend, not an upstream dialer")
	}
	if c.profile != nil {
		return c.withShadowTLS(*c.profile, nil)
	}
	return c.withShadowTLS(accesskey.NewResolverWithTransport(t).Resolve(ctx, c.key))
}

func (c *File) withShadowTLS(p accesskey.Profile, err error) (accesskey.Profile, error) {
	if p.SSPlugin != nil {
		plugin := *p.SSPlugin
		p.SSPlugin = &plugin
	}
	if p.ShadowTLS != nil {
		settings := *p.ShadowTLS
		p.ShadowTLS = &settings
	}
	if err != nil {
		return accesskey.Profile{}, err
	}
	if c.ShadowTLS != nil {
		settings := *c.ShadowTLS
		p.ShadowTLS = &settings
	}
	if err := p.ValidateShadowTLS(); err != nil {
		return accesskey.Profile{}, err
	}
	return p, nil
}
func (c *File) VPNPolicy() (*routing.Policy, error) {
	return c.RoutingPolicy()
}

// RoutingPolicy compiles against the immutable dataset snapshot loaded with this profile.
func (c *File) RoutingPolicy() (*routing.Policy, error) {
	return routing.CompileWithGeoData(c.Routing, c.geoData)
}

func readGeoData(profile, resource, kind string) ([]byte, error) {
	if resource == "" {
		return nil, &routing.GeoDataError{Code: "geodata_required", Kind: kind, Err: fmt.Errorf("dataset file required")}
	}
	if !filepath.IsAbs(resource) {
		resource = filepath.Join(filepath.Dir(profile), resource)
	}
	f, err := geofile.Open(resource)
	if err != nil {
		return nil, &routing.GeoDataError{Code: "geodata_unreadable", Kind: kind, Err: fmt.Errorf("dataset file unreadable")}
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 64*1024*1024+1))
	if err != nil {
		return nil, &routing.GeoDataError{Code: "geodata_unreadable", Kind: kind, Err: fmt.Errorf("dataset file unreadable")}
	}
	if len(b) > 64*1024*1024 {
		return nil, &routing.GeoDataError{Code: "geodata_limit", Kind: kind, Err: fmt.Errorf("dataset exceeds size limit")}
	}
	return b, nil
}
