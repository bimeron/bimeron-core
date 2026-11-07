package config

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"bimeron/internal/problem"
	"bimeron/internal/routing"
)

const sentinel = "Sentinel7secret"

// uriSeeds complement examples/*.conf with URI-based access keys. Secrets
// contain the sentinel so leak checks can find them.
func uriSeeds() map[string]string {
	vmess := base64.StdEncoding.EncodeToString([]byte(`{"v":"2","add":"example.com","port":"443","id":"123e4567-e89b-12d3-a456-426614174000","aid":"0","scy":"auto","net":"ws","tls":"tls","path":"/ws","host":"cdn.example.com"}`))
	keys := map[string]string{
		"vless-reality": "VLESS = vless://123e4567-e89b-12d3-a456-426614174000@example.com:443?encryption=none&type=tcp&flow=xtls-rprx-vision&security=reality&sni=example.com&fp=chrome&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=abcd",
		"vless-ws":      "VLESS = vless://123e4567-e89b-12d3-a456-426614174000@example.com:443?encryption=none&security=tls&type=ws&path=%2Fws&host=cdn.example.com&alpn=http%2F1.1",
		"vless-grpc":    "VLESS = vless://123e4567-e89b-12d3-a456-426614174000@example.com:443?encryption=none&security=tls&type=grpc&serviceName=svc&mode=multi",
		"vless-xhttp":   "VLESS = vless://123e4567-e89b-12d3-a456-426614174000@example.com:443?encryption=none&security=tls&type=xhttp&mode=packet-up&path=%2Fx&alpn=h2",
		"vmess":         "VMess = vmess://" + vmess,
		"trojan":        "Trojan = trojan://" + sentinel + "@example.com:443?security=tls&type=ws&path=%2Fws&sni=example.com",
		"hysteria2":     "Hysteria2 = hysteria2://" + sentinel + "@example.com:443?sni=example.com",
		"tuic":          "TUIC = tuic://123e4567-e89b-12d3-a456-426614174000:" + sentinel + "@example.com:443?sni=front.example&alpn=h3&udp_relay_mode=quic",
		"anytls":        "AnyTLS = anytls://" + sentinel + "@example.com:443?sni=example.com",
		"ssh":           "SSH = ssh://alice@ssh.example.com:22",
		"ss":            "SS = ss://aes-256-gcm:" + sentinel + "@example.com:8388",
		"ss-plugin":     "SS = ss://aes-256-gcm:" + sentinel + "@example.com:8388/?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dexample.com",
		"ss2022":        "SS = ss://2022-blake3-aes-128-gcm:" + base64.StdEncoding.EncodeToString([]byte("0123456789abcdef")) + "@example.com:8388",
		"naive":         "Naive = naive+https://alice:" + sentinel + "@example.com:443?sni=example.com",
		"naive-quic":    "Naive = naive+quic://alice:" + sentinel + "@example.com:443",
		"masque":        "MASQUE = masque://alice:" + sentinel + "@proxy.example:443?sni=tls.example",
		"socks5":        "SOCKS5 = socks5://alice:" + sentinel + "@proxy.example.com:1080",
		"http":          "HTTP = https://alice:" + sentinel + "@proxy.example.com:443",
		"ssconf":        "SSConf = ssconf://example.com/key.json",
	}
	seeds := map[string]string{}
	for name, key := range keys {
		mode := "vpn"
		if strings.HasPrefix(name, "ssh") || strings.HasPrefix(name, "naive") || name == "masque" {
			mode = "proxy"
		}
		seeds["uri-"+name] = "[Profile]\nVersion = 1\nName = Seed\n\n[AccessKey]\n" + key + "\n\n[Interface]\nMode = " + mode + "\n\n[Routing]\nDefault = proxy\n\n[Rule]\nCIDR = 10.0.0.0/8\nAction = direct\n\n[Rule]\nDomain = example.org\nAction = proxy\n"
	}
	seeds["explicit-ss-shadowtls"] = "[Profile]\nVersion = 1\n\n[AccessKey]\nType = shadowsocks\nServer = example.com\nPort = 443\nMethod = aes-256-gcm\nPassword = " + sentinel + "\n\n[ShadowTLS]\nServerName = handshake.example.com\nPassword = " + sentinel + "\n\n[Interface]\nMode = vpn\nIPv6 = disable\nKillSwitch = true\nMTU = 1400\nDNS = 1.1.1.1, 8.8.8.8\nName = Tun0\n"
	return seeds
}

func seedProfiles(t *testing.T) map[string]string {
	seeds := uriSeeds()
	paths, err := filepath.Glob(filepath.Join("..", "..", "examples", "*.conf"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		seeds["example-"+filepath.Base(path)] = string(b)
	}
	return seeds
}

func valueMutations(value string) []string {
	out := []string{"", "x", "-1", "0", "70000", "a b/c", value + "x", value + value, "\"unterminated"}
	if len(value) > 1 {
		out = append(out, value[:len(value)/2])
	}
	if strings.Contains(value, "://") {
		out = append(out, uriMutations(value)...)
	}
	return out
}

func uriMutations(raw string) []string {
	u, err := url.Parse(raw)
	if err != nil {
		return nil
	}
	var out []string
	add := func(m func(*url.URL)) {
		c := *u
		if u.User != nil {
			user := *u.User
			c.User = &user
		}
		m(&c)
		out = append(out, c.String())
	}
	add(func(c *url.URL) { c.Scheme += "x" })
	add(func(c *url.URL) { c.User = nil })
	add(func(c *url.URL) { c.User = url.User("x") })
	add(func(c *url.URL) { c.User = url.UserPassword("x", "") })
	add(func(c *url.URL) { c.Host = "" })
	add(func(c *url.URL) { c.Host = "example.com:0" })
	add(func(c *url.URL) { c.Host = "example.com:70000" })
	add(func(c *url.URL) { c.Host = "example.com:x" })
	add(func(c *url.URL) { c.Host = "example.com" })
	add(func(c *url.URL) { c.Path = "/extra" })
	add(func(c *url.URL) { c.RawQuery += "&zz=1" })
	q := u.Query()
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range []string{"", "x", "-1", "h3", "none", "reality", "tls", "ws", "grpc", "xhttp", "tcp", "stream-one", "/p", "chrome"} {
			k, v := k, v
			add(func(c *url.URL) { m := c.Query(); m.Set(k, v); c.RawQuery = m.Encode() })
		}
		add(func(c *url.URL) { m := c.Query(); m.Del(k); c.RawQuery = m.Encode() })
		add(func(c *url.URL) { m := c.Query(); m.Add(k, m.Get(k)); c.RawQuery = m.Encode() })
	}
	if u.Scheme == "vmess" {
		out = append(out, "vmess://", "vmess://e30=", "vmess://"+base64.StdEncoding.EncodeToString([]byte(`{"add":"example.com"}`)))
	}
	return out
}

// mutations derives malformed profiles from a valid one.
func mutations(profile string) []string {
	lines := strings.Split(profile, "\n")
	var out []string
	with := func(i int, replacement ...string) {
		m := append(append(append([]string{}, lines[:i]...), replacement...), lines[i+1:]...)
		out = append(out, strings.Join(m, "\n"))
	}
	for i, line := range lines {
		text := strings.TrimSpace(line)
		if text == "" || strings.HasPrefix(text, "#") || strings.HasPrefix(text, ";") {
			continue
		}
		with(i)
		with(i, line, line)
		if strings.HasPrefix(text, "[") {
			with(i, "[Bogus]")
			with(i, "[Rule")
			continue
		}
		key, value, _ := strings.Cut(text, "=")
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		with(i, key)
		with(i, key+"x = "+value)
		for _, v := range valueMutations(value) {
			with(i, key+" = "+v)
		}
	}
	out = append(out, "[Profile]\nVersion = 2\n", "garbage", "[Profile]\nVersion = 1\n", "\xff\xfe")
	for _, extra := range []string{"Type = vless", "Username = bob", "ServerName = s.example", "Method = aes-256-gcm", "Prefix = x", "Plugin = obfs-local", "IdentityFile = id", "MASQUEPath = /x", "CAFile = ca.pem", "XHTTPExtra = {}", "XHTTPNoGRPCHeader = true", "ID = 123e4567-e89b-12d3-a456-426614174000", "Flow = xtls-rprx-vision", "WSPath = /ws", "Password = " + sentinel, "Key = ss://x", "SS = ss://x"} {
		out = append(out, strings.Replace(profile, "[AccessKey]\n", "[AccessKey]\n"+extra+"\n", 1))
	}
	for _, extra := range []string{"GeoIP = ru\nAction = direct", "GeoSite = ru\nAction = direct", "CIDR = 10.0.0.0/33\nAction = direct", "Domain = \nAction = direct", "CIDR = 10.0.0.0/8\nAction = drop", "CIDR = 10.0.0.0/8\nDomain = a.example\nAction = direct", "Action = direct"} {
		out = append(out, profile+"\n[Rule]\n"+extra+"\n")
	}
	return out
}

var canonicalFields = map[string]bool{}

func init() {
	for _, f := range strings.Fields(`Version Name Mode MTU DNS IPv6 KillSwitch Listen Default CIDR Domain GeoIP GeoSite Action
		GeoIPFile GeoSiteFile ServerName Password WindowsProfile
		File Key SS SSConf SOCKS5 HTTP VLESS VMess Trojan Naive Hysteria2 AnyTLS SSH TUIC MASQUE
		Type Server Port Method Prefix Username Plugin PluginOpts IdentityFile KnownHostsFile MASQUEPath CAFile
		ID Encryption Flow Network Security PublicKey ShortID Fingerprint SpiderX ALPN WSPath WSHost WSEarlyData
		GRPCServiceName GRPCAuthority GRPCMultiMode XHTTPPath XHTTPHost XHTTPMode XHTTPExtra`) {
		canonicalFields[f] = true
	}
}

func knownField(field string) bool {
	if field == "" || canonicalFields[field] || strings.HasPrefix(field, "XHTTP") {
		return true
	}
	_, ok := problem.MustLoad().URIFields[field]
	return ok
}

// TestEveryValidationFailureIsCoded loads many malformed profiles and requires
// each failure to be a located, catalog-coded problem without secrets.
func TestEveryValidationFailureIsCoded(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profile.conf")
	seeds := seedProfiles(t)
	names := make([]string, 0, len(seeds))
	for name := range seeds {
		names = append(names, name)
	}
	sort.Strings(names)
	failures := map[string]string{}
	checked := 0
	for _, name := range names {
		seed := seeds[name]
		if err := os.WriteFile(path, []byte(seed), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err != nil && !strings.Contains(seed, "File =") && !strings.Contains(seed, "IKEv2") {
			t.Errorf("seed %s is invalid: %v", name, err)
			continue
		}
		for _, mutated := range mutations(seed) {
			if err := os.WriteFile(path, []byte(mutated), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := Load(path)
			if err == nil {
				continue
			}
			checked++
			key := ""
			p, ok := problem.As(err)
			switch {
			case !ok:
				key = "uncoded: " + err.Error()
			case p.Code == problem.Unclassified:
				key = "unclassified: " + p.Message
			case !problem.Known(p.Code):
				key = "unknown code " + p.Code + ": " + p.Message
			case p.Field != "" && p.Section == "":
				key = fmt.Sprintf("field without section %s/%s: %s", p.Code, p.Field, p.Message)
			case !knownField(p.Field) || !knownField(p.Source):
				key = fmt.Sprintf("non-canonical field %q source %q: %s", p.Field, p.Source, p.Message)
			}
			if ok {
				data, _ := json.Marshal(p)
				if strings.Contains(strings.ToLower(string(data)), strings.ToLower(sentinel)) {
					key = "secret leaked: " + string(data)
				}
				for _, value := range p.Args {
					if len(value) > 200 {
						key = "unsafe arg: " + string(data)
					}
				}
			}
			if key != "" {
				if _, seen := failures[key]; !seen {
					failures[key] = name
				}
			}
		}
	}
	if checked < 1000 {
		t.Errorf("only %d malformed profiles were rejected; the corpus is too small", checked)
	}
	keys := make([]string, 0, len(failures))
	for key := range failures {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		t.Errorf("%s (seed %s)", key, failures[key])
	}
}

func TestProblemLocations(t *testing.T) {
	// rules ends with an empty second [Rule] section at line 11.
	const rules = "[Profile]\nVersion = 1\n\n[AccessKey]\nSS = ss://aes-256-gcm:s@example.com:8388\n\n[Rule]\nCIDR = 10.0.0.0/8\nAction = direct\n\n[Rule]\n"
	cases := []struct {
		name, profile, code, section, field, source string
		line, rule                                  int
	}{
		{"interface name", "[Profile]\nVersion = 1\n\n[AccessKey]\nSS = ss://aes-256-gcm:s@example.com:8388\n\n[Interface]\nName = 1bad\n", "interface_name_invalid", "Interface", "Name", "", 8, 0},
		{"unknown option", "[Profile]\nVersion = 1\nColor = red\n", "option_unknown", "Profile", "", "", 3, 0},
		{"rule kill switch", "[Profile]\nVersion = 1\n\n[AccessKey]\nSS = ss://aes-256-gcm:s@example.com:8388\n\n[Interface]\nKillSwitch = true\n\n[Rule]\nCIDR = 10.0.0.0/8\nAction = direct\n\n[Rule]\nDomain = example.org\nAction = direct\n", "kill_switch_cidr_only", "Rule", "Domain", "", 15, 2},
		{"uri scheme", "[Profile]\nVersion = 1\n\n[AccessKey]\nVLESS = trojan://x@example.com:443\n", "uri_scheme_invalid", "AccessKey", "", "VLESS", 5, 0},
		{"missing type", "[Profile]\nVersion = 1\n\n[AccessKey]\nServer = example.com\nPort = 443\n", "value_required", "AccessKey", "Type", "", 4, 0},
		{"credentials", "[Profile]\nVersion = 1\n\n[AccessKey]\nType = socks5\nServer = example.com\nPort = 1080\nUsername = alice\n", "credentials_incomplete", "AccessKey", "Password", "", 4, 0},
		{"rule cidr", rules + "CIDR = 10.0.0.0/33\nAction = direct\n", "cidr_invalid", "Rule", "CIDR", "", 12, 2},
		{"rule domain", rules + "Domain = a b\nAction = direct\n", "domain_invalid", "Rule", "Domain", "", 12, 2},
		{"rule action", rules + "Domain = example.org\nAction = drop\n", "choice_invalid", "Rule", "Action", "", 13, 2},
		{"rule matcher", rules + "Action = direct\n", "rule_matcher_count", "Rule", "", "", 11, 2},
		{"rule two matchers", rules + "Domain = example.org\nCIDR = 10.0.0.0/8\nAction = direct\n", "rule_matcher_count", "Rule", "CIDR", "", 13, 2},
		{"rule geoip without dataset", rules + "GeoIP = ru\nAction = direct\n", "geodata_required", "Rule", "GeoIP", "", 12, 2},
		{"routing default", "[Profile]\nVersion = 1\n\n[AccessKey]\nSS = ss://aes-256-gcm:s@example.com:8388\n\n[Routing]\nDefault = drop\n", "choice_invalid", "Routing", "Default", "", 8, 0},
		{"ikev2 server name", "[Profile]\nVersion = 1\n\n[IKEv2]\nWindowsProfile = Work\nServerName = 10.0.0.1\n", "ikev2_server_name_requires_dns_name", "IKEv2", "ServerName", "", 6, 0},
		{"ikev2 windows profile", "[Profile]\nVersion = 1\n\n[IKEv2]\nWindowsProfile = Work/VPN\nServerName = vpn.example.com\n", "ikev2_invalid_windows_profile", "IKEv2", "WindowsProfile", "", 5, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseData([]byte(tc.profile))
			p, ok := problem.As(err)
			if !ok {
				t.Fatalf("error = %v", err)
			}
			if p.Code != tc.code || p.Section != tc.section || p.Field != tc.field || p.Source != tc.source || p.Line != tc.line || p.Rule != tc.rule {
				t.Fatalf("problem = %+v", p)
			}
		})
	}
}

// TestGeoDataFileProblems locates dataset file failures at [GeoData] options.
func TestGeoDataFileProblems(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profile.conf")
	base := "[Profile]\nVersion = 1\n\n[AccessKey]\nSS = ss://aes-256-gcm:s@example.com:8388\n\n"
	for _, tc := range []struct {
		name, profile, code, field string
		line                       int
	}{
		{"missing file option", base + "[Rule]\nGeoSite = ru\nAction = direct\n", "geodata_required", "GeoSiteFile", 0},
		{"unreadable file", base + "[GeoData]\nGeoIPFile = missing.dat\n\n[Rule]\nGeoIP = ru\nAction = direct\n", "geodata_unreadable", "GeoIPFile", 8},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(tc.profile), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := Load(path)
			p, ok := problem.As(err)
			if !ok || p.Code != tc.code || p.Section != "GeoData" || p.Field != tc.field || p.Line != tc.line || p.Rule != 0 {
				t.Fatalf("problem = %+v (%v)", p, err)
			}
			var ge *routing.GeoDataError
			if !errors.As(err, &ge) || ge.Code != tc.code {
				t.Fatalf("GeoDataError lost: %v", err)
			}
		})
	}
}
