package config

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"

	"bimeron/internal/accesskey"
	"bimeron/internal/problem"
)

// AccessOption is one [AccessKey] option written by a source conversion.
type AccessOption struct{ Key, Value string }

// AccessConversion rewrites an [AccessKey] source: the Remove options are
// replaced by Add, in order. Other options, such as SSH file paths, remain.
type AccessConversion struct {
	Remove []string
	Add    []AccessOption
}

// uriSources are the [AccessKey] options holding a share URI that converts to
// explicit parameters. SSConf and File resolve their key only when connecting.
var uriSources = []string{"SS", "SOCKS5", "HTTP", "MASQUE", "VLESS", "VMess", "Trojan", "Naive", "Hysteria2", "AnyTLS", "SSH", "TUIC", "Key"}

// keptOptions survive a conversion to a URI; the URI does not replace them.
var keptOptions = []string{"IdentityFile", "KnownHostsFile"}

// ConvertAccess converts decoded [AccessKey] options between a share URI and
// explicit parameters. It resolves both forms and fails unless they produce an
// equivalent runtime profile. Errors never contain option values.
func ConvertAccess(options map[string]string, toFields bool) (AccessConversion, error) {
	source := ""
	for _, key := range append([]string{"SSConf", "File"}, uriSources...) {
		if options[key] != "" {
			source = key
			break
		}
	}
	unsupported := func(field string) error {
		p := problem.New("access_conversion_unsupported", "[AccessKey] source cannot be converted").In("AccessKey")
		if field != "" {
			p.At(field)
		}
		return p
	}
	switch {
	case source == "SSConf" || source == "File" || (source == "Key" && strings.HasPrefix(strings.TrimSpace(options["Key"]), "ssconf://")):
		return AccessConversion{}, unsupported(source)
	case toFields && source == "":
		return AccessConversion{}, unsupported(firstOption(options, "Type"))
	case !toFields && options["Type"] == "":
		return AccessConversion{}, unsupported(source)
	}
	p, err := resolveAccessOptions(options)
	if err != nil {
		return AccessConversion{}, err
	}
	var conv AccessConversion
	if toFields {
		conv, err = explicitConversion(p, source, options)
	} else {
		conv, err = uriConversion(p, options)
	}
	if err != nil {
		return AccessConversion{}, err
	}
	next := map[string]string{}
	for key, value := range options {
		if !slices.Contains(conv.Remove, key) {
			next[key] = value
		}
	}
	for _, option := range conv.Add {
		next[option.Key] = option.Value
	}
	converted, err := resolveAccessOptions(next)
	if err != nil || !accesskey.Equivalent(p, converted) {
		return AccessConversion{}, problem.New("access_conversion_mismatch", "[AccessKey] converted source does not match the original").In("AccessKey")
	}
	return conv, nil
}

func firstOption(options map[string]string, key string) string {
	if options[key] != "" {
		return key
	}
	return ""
}

// resolveAccessOptions resolves [AccessKey] options alone, so routing resources and
// other sections cannot affect the comparison. Problems keep their field but
// lose line numbers, which refer to this synthetic profile.
func resolveAccessOptions(options map[string]string) (accesskey.Profile, error) {
	keys := make([]string, 0, len(options))
	for key := range options {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString("[Profile]\nVersion = 1\n[AccessKey]\n")
	for _, key := range keys {
		b.WriteString(key + " = " + strconv.Quote(options[key]) + "\n")
	}
	c, err := ParseData([]byte(b.String()))
	if err == nil {
		var p accesskey.Profile
		p, err = c.Resolve(context.Background())
		if err == nil {
			return p, nil
		}
	}
	located := problem.Of(err)
	located.Line = 0
	return accesskey.Profile{}, located
}

// explicitConversion replaces a URI source with explicit options.
func explicitConversion(p accesskey.Profile, source string, options map[string]string) (AccessConversion, error) {
	uri := strings.TrimSpace(options[source])
	var add []AccessOption
	set := func(key, value string) {
		if value != "" {
			add = append(add, AccessOption{key, value})
		}
	}
	typ := p.Type
	if typ == "" {
		typ = "shadowsocks"
	}
	if typ == "http" && p.HTTPServerName != "" {
		typ = "https"
	}
	set("Type", typ)
	set("Server", p.TCP.Host)
	set("Port", strconv.Itoa(p.TCP.Port))
	switch typ {
	case "shadowsocks":
		set("Method", p.TCP.Cipher)
		set("Password", p.TCP.Secret)
		set("Prefix", p.TCP.Prefix)
		if p.SSPlugin != nil {
			name, opts, _ := strings.Cut(ssPluginQuery(uri), ";")
			set("Plugin", name)
			set("PluginOpts", opts)
		}
	case "socks5", "http", "https":
		set("Username", p.Username)
		set("Password", p.TCP.Secret)
	case "vless":
		v := p.VLESS
		set("ID", v.ID)
		set("Encryption", v.Encryption)
		set("Flow", v.Flow)
		set("Network", v.Network)
		set("Security", v.Security)
		set("ServerName", v.ServerName)
		set("PublicKey", v.PublicKey)
		set("ShortID", v.ShortID)
		set("Fingerprint", v.Fingerprint)
		set("SpiderX", v.SpiderX)
		set("ALPN", v.ALPN)
		set("WSPath", v.WSPath)
		set("WSHost", v.WSHost)
		if v.WSEarlyData != 0 {
			set("WSEarlyData", strconv.Itoa(v.WSEarlyData))
		}
		set("GRPCServiceName", v.GRPCServiceName)
		set("GRPCAuthority", v.GRPCAuthority)
		if v.GRPCMultiMode {
			set("GRPCMultiMode", "true")
		}
		set("XHTTPPath", v.XHTTPPath)
		set("XHTTPHost", v.XHTTPHost)
		set("XHTTPMode", v.XHTTPMode)
		if v.XHTTPOptions != nil {
			if u, err := url.Parse(uri); err == nil {
				q, _ := url.ParseQuery(u.RawQuery)
				set("XHTTPExtra", q.Get("extra"))
			}
		}
	case "vmess":
		v := p.VMess
		set("ID", v.ID)
		set("Encryption", v.Security)
		set("Network", v.Network)
		set("Security", v.TLS)
		set("ServerName", v.ServerName)
		set("ALPN", v.ALPN)
		set("Fingerprint", v.Fingerprint)
		set("PublicKey", v.PublicKey)
		set("ShortID", v.ShortID)
		set("SpiderX", v.SpiderX)
		set("WSPath", v.WSPath)
		set("WSHost", v.WSHost)
		set("GRPCServiceName", v.GRPCServiceName)
		set("GRPCAuthority", v.GRPCAuthority)
		if v.GRPCMultiMode {
			set("GRPCMultiMode", "true")
		}
		set("XHTTPPath", v.XHTTPPath)
		set("XHTTPHost", v.XHTTPHost)
		set("XHTTPMode", v.XHTTPMode)
		if v.XHTTPOptions != nil {
			set("XHTTPExtra", vmessExtra(uri))
		}
	case "trojan":
		t := p.Trojan
		set("Password", t.Password)
		set("ServerName", t.ServerName)
		set("Network", t.Network)
		set("ALPN", t.ALPN)
		set("WSPath", t.WSPath)
		set("WSHost", t.WSHost)
		set("GRPCServiceName", t.GRPCServiceName)
		set("GRPCAuthority", t.GRPCAuthority)
		if t.GRPCMultiMode {
			set("GRPCMultiMode", "true")
		}
	case "naive":
		set("Username", p.Naive.User)
		set("Password", p.Naive.Password)
		set("ServerName", p.Naive.ServerName)
		if p.Naive.QUIC {
			set("Network", "quic")
		}
	case "hysteria2":
		h := p.Hysteria2
		set("Password", h.Password)
		set("ServerName", h.ServerName)
		set("ALPN", h.ALPN)
		set("Fingerprint", h.Fingerprint)
	case "anytls":
		set("Password", p.AnyTLS.Password)
		set("ServerName", p.AnyTLS.ServerName)
	case "tuic":
		t := p.TUIC
		set("ID", t.ID)
		set("Password", t.Password)
		set("ServerName", t.ServerName)
		set("ALPN", t.ALPN)
	case "ssh":
		set("Username", p.SSH.User)
		// File paths from the URI become options; existing options stay.
		if options["IdentityFile"] == "" {
			set("IdentityFile", p.SSH.IdentityFile)
		}
		if options["KnownHostsFile"] == "" {
			set("KnownHostsFile", p.SSH.KnownHostsFile)
		}
	case "masque":
		m := p.MASQUE
		set("Username", p.Username)
		set("Password", p.TCP.Secret)
		set("ServerName", m.ServerName)
		if m.UDPPath != accesskey.DefaultMASQUEPath {
			set("MASQUEPath", m.UDPPath)
		}
		set("CAFile", m.CAFile)
	default:
		return AccessConversion{}, problem.New("access_conversion_unsupported", "[AccessKey] source cannot be converted").In("AccessKey").At(source)
	}
	return AccessConversion{Remove: []string{source}, Add: add}, nil
}

// uriConversion replaces explicit options with the protocol's share URI.
func uriConversion(p accesskey.Profile, options map[string]string) (AccessConversion, error) {
	var remove []string
	for key := range options {
		if !slices.Contains(keptOptions, key) {
			remove = append(remove, key)
		}
	}
	sort.Strings(remove)
	host := net.JoinHostPort(p.TCP.Host, strconv.Itoa(p.TCP.Port))
	q := url.Values{}
	set := func(key, value string) {
		if value != "" {
			q.Set(key, value)
		}
	}
	link := func(scheme string, user *url.Userinfo) string {
		u := url.URL{Scheme: scheme, User: user, Host: host, RawQuery: q.Encode()}
		return u.String()
	}
	extra, err := explicitExtra(options)
	if err != nil {
		return AccessConversion{}, err
	}
	field, uri := "", ""
	switch p.Type {
	case "":
		field = "SS"
		set("prefix", p.TCP.Prefix)
		if options["Plugin"] != "" {
			plugin := options["Plugin"]
			if options["PluginOpts"] != "" {
				plugin += ";" + options["PluginOpts"]
			}
			set("plugin", plugin)
		}
		uri = "ss://" + base64.RawURLEncoding.EncodeToString([]byte(p.TCP.Cipher+":"+p.TCP.Secret)) + "@" + host
		if len(q) > 0 {
			uri += "?" + q.Encode()
		}
	case "socks5", "http":
		field = map[string]string{"socks5": "SOCKS5", "http": "HTTP"}[p.Type]
		scheme := p.Type
		if p.HTTPServerName != "" {
			scheme = "https"
		}
		var user *url.Userinfo
		if p.Username != "" {
			user = url.UserPassword(p.Username, p.TCP.Secret)
		}
		uri = link(scheme, user)
	case "vless":
		field = "VLESS"
		v := p.VLESS
		set("encryption", v.Encryption)
		set("flow", v.Flow)
		set("type", v.Network)
		set("security", v.Security)
		set("sni", v.ServerName)
		set("pbk", v.PublicKey)
		set("sid", v.ShortID)
		set("fp", v.Fingerprint)
		set("spx", v.SpiderX)
		set("alpn", v.ALPN)
		switch v.Network {
		case "grpc":
			set("serviceName", v.GRPCServiceName)
			set("authority", v.GRPCAuthority)
			if v.GRPCMultiMode {
				set("mode", "multi")
			}
		case "xhttp":
			set("path", v.XHTTPPath)
			set("host", v.XHTTPHost)
			set("mode", v.XHTTPMode)
			set("extra", extra)
		default:
			set("path", v.WSPath)
			set("host", v.WSHost)
			if v.WSEarlyData != 0 {
				set("ed", strconv.Itoa(v.WSEarlyData))
			}
		}
		uri = link("vless", url.User(v.ID))
	case "vmess":
		field = "VMess"
		v := p.VMess
		object := map[string]string{"v": "2", "add": p.TCP.Host, "port": strconv.Itoa(p.TCP.Port), "id": v.ID, "scy": v.Security,
			"net": v.Network, "tls": v.TLS, "sni": v.ServerName, "alpn": v.ALPN, "fp": v.Fingerprint, "pbk": v.PublicKey, "sid": v.ShortID, "spx": v.SpiderX}
		switch v.Network {
		case "grpc":
			object["path"], object["host"] = v.GRPCServiceName, v.GRPCAuthority
			if v.GRPCMultiMode {
				object["mode"] = "multi"
			}
		case "xhttp":
			object["path"], object["host"], object["mode"], object["extra"] = v.XHTTPPath, v.XHTTPHost, v.XHTTPMode, extra
		default:
			object["path"], object["host"] = v.WSPath, v.WSHost
		}
		for key, value := range object {
			if value == "" {
				delete(object, key)
			}
		}
		data, _ := json.Marshal(object)
		uri = "vmess://" + base64.StdEncoding.EncodeToString(data)
	case "trojan":
		field = "Trojan"
		t := p.Trojan
		set("sni", t.ServerName)
		set("type", t.Network)
		set("alpn", t.ALPN)
		set("path", t.WSPath)
		set("host", t.WSHost)
		set("serviceName", t.GRPCServiceName)
		set("authority", t.GRPCAuthority)
		if t.GRPCMultiMode {
			set("mode", "multi")
		}
		uri = link("trojan", url.User(t.Password))
	case "naive":
		field = "Naive"
		set("sni", p.Naive.ServerName)
		scheme := "naive+https"
		if p.Naive.QUIC {
			scheme = "naive+quic"
		}
		uri = link(scheme, url.UserPassword(p.Naive.User, p.Naive.Password))
	case "hysteria2":
		field = "Hysteria2"
		h := p.Hysteria2
		set("sni", h.ServerName)
		set("alpn", h.ALPN)
		set("fp", h.Fingerprint)
		uri = link("hysteria2", url.User(h.Password))
	case "anytls":
		field = "AnyTLS"
		set("sni", p.AnyTLS.ServerName)
		uri = link("anytls", url.User(p.AnyTLS.Password))
	case "tuic":
		field = "TUIC"
		set("sni", p.TUIC.ServerName)
		set("alpn", p.TUIC.ALPN)
		uri = link("tuic", url.UserPassword(p.TUIC.ID, p.TUIC.Password))
	case "ssh":
		// IdentityFile and KnownHostsFile stay as options.
		field = "SSH"
		uri = link("ssh", url.User(p.SSH.User))
	case "masque":
		field = "MASQUE"
		m := p.MASQUE
		set("sni", m.ServerName)
		if m.UDPPath != accesskey.DefaultMASQUEPath {
			set("udp_path", m.UDPPath)
		}
		set("ca", m.CAFile)
		var user *url.Userinfo
		if p.Username != "" {
			user = url.UserPassword(p.Username, p.TCP.Secret)
		}
		uri = link("masque", user)
	default:
		return AccessConversion{}, problem.New("access_conversion_unsupported", "[AccessKey] source cannot be converted").In("AccessKey").At("Type")
	}
	return AccessConversion{Remove: remove, Add: []AccessOption{{field, uri}}}, nil
}

// explicitExtra returns the XHTTP extra JSON of explicit options, combining
// separate XHTTP options when XHTTPExtra is absent.
func explicitExtra(options map[string]string) (string, error) {
	if options["XHTTPExtra"] != "" {
		return options["XHTTPExtra"], nil
	}
	separate := map[string]string{}
	for key, value := range options {
		if strings.HasPrefix(key, "XHTTP") && key != "XHTTPPath" && key != "XHTTPHost" && key != "XHTTPMode" {
			separate[key] = value
		}
	}
	if len(separate) == 0 {
		return "", nil
	}
	extra, err := accesskey.XHTTPExtraJSON(separate)
	if err != nil {
		return "", accessProblem(err)
	}
	return extra, nil
}

// ssPluginQuery returns the decoded plugin query value of a SIP002 URI.
func ssPluginQuery(uri string) string {
	body, _, _ := strings.Cut(uri, "#")
	at := strings.LastIndex(body, "@")
	if at < 0 {
		return ""
	}
	_, query, ok := strings.Cut(body[at:], "?")
	if !ok {
		return ""
	}
	q, _ := url.ParseQuery(query)
	return q.Get("plugin")
}

// vmessExtra returns the extra string of a VMess share payload.
func vmessExtra(uri string) string {
	payload := strings.TrimPrefix(uri, "vmess://")
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		decoded, err := encoding.DecodeString(payload)
		if err != nil {
			continue
		}
		var fields map[string]json.RawMessage
		var extra string
		if json.Unmarshal(decoded, &fields) == nil && json.Unmarshal(fields["extra"], &extra) == nil {
			return extra
		}
		return ""
	}
	return ""
}
