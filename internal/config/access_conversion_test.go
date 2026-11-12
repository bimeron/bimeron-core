package config

import (
	"encoding/base64"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"bimeron/internal/accesskey"
	"bimeron/internal/problem"
)

func applyConversion(options map[string]string, conv AccessConversion) map[string]string {
	next := map[string]string{}
	for key, value := range options {
		if !slices.Contains(conv.Remove, key) {
			next[key] = value
		}
	}
	for _, option := range conv.Add {
		next[option.Key] = option.Value
	}
	return next
}

func mustConvert(t *testing.T, options map[string]string, toFields bool) map[string]string {
	t.Helper()
	conv, err := ConvertAccess(options, toFields)
	if err != nil {
		t.Fatalf("convert (to fields %v): %v", toFields, err)
	}
	return applyConversion(options, conv)
}

func mustResolve(t *testing.T, options map[string]string) accesskey.Profile {
	t.Helper()
	p, err := resolveAccessOptions(options)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	return p
}

func vmessURI(json string) string {
	return "vmess://" + base64.StdEncoding.EncodeToString([]byte(json))
}

// TestAccessConversionRoundTrips converts every URI source to explicit
// parameters and back; both steps keep the runtime profile.
func TestAccessConversionRoundTrips(t *testing.T) {
	ca := filepath.Join(t.TempDir(), "ca.pem")
	ssKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	cases := []struct {
		name    string
		options map[string]string
		typ     string
	}{
		{"ss", map[string]string{"SS": "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:p@ss:w#rd")) + "@example.com:8388#Name"}, "shadowsocks"},
		{"ss-prefix", map[string]string{"SS": "ss://aes-128-gcm:secret@example.com:443?prefix=%16%03%01"}, "shadowsocks"},
		{"ss-plugin", map[string]string{"SS": "ss://aes-128-gcm:secret@example.com:443?plugin=v2ray-plugin%3Btls%3Bhost%3Dcdn.example.com%3Bpath%3D%2Fws"}, "shadowsocks"},
		{"ss2022", map[string]string{"SS": "ss://" + base64.RawURLEncoding.EncodeToString([]byte("2022-blake3-aes-256-gcm:"+ssKey)) + "@[2001:db8::1]:443"}, "shadowsocks"},
		{"socks5", map[string]string{"SOCKS5": "socks5://example.com:1080"}, "socks5"},
		{"socks5-auth", map[string]string{"SOCKS5": "socks5://al%40ice:p%3Ass@example.com:1080"}, "socks5"},
		{"http", map[string]string{"HTTP": "http://example.com:8080"}, "http"},
		{"https-auth", map[string]string{"HTTP": "https://alice:secret@example.com:443"}, "https"},
		{"vless-reality", map[string]string{"VLESS": "vless://" + testUUID + "@example.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=front.example&fp=chrome&pbk=" + realityKey + "&sid=abcd&spx=%2Fs&type=tcp"}, "vless"},
		{"vless-ws", map[string]string{"VLESS": "vless://" + testUUID + "@example.com:443?encryption=none&security=tls&type=ws&path=%2Fws&host=cdn.example.com&ed=2048&alpn=http%2F1.1"}, "vless"},
		{"vless-grpc", map[string]string{"VLESS": "vless://" + testUUID + "@example.com:443?encryption=none&security=tls&type=grpc&serviceName=svc&authority=auth.example&mode=multi"}, "vless"},
		{"vless-xhttp", map[string]string{"VLESS": "vless://" + testUUID + "@example.com:443?encryption=none&security=tls&type=xhttp&path=%2Fx&mode=packet-up&extra=%7B%22xPaddingBytes%22%3A%22100-1000%22%7D"}, "vless"},
		{"key-vless", map[string]string{"Key": "vless://" + testUUID + "@example.com:443?encryption=none&security=tls&type=tcp"}, "vless"},
		{"vmess-ws", map[string]string{"VMess": vmessURI(`{"v":"2","ps":"Name","add":"example.com","port":443,"id":"` + testUUID + `","aid":"0","scy":"chacha20-poly1305","net":"ws","path":"/ws","host":"cdn.example.com","tls":"tls","sni":"front.example","fp":"firefox"}`)}, "vmess"},
		{"vmess-grpc", map[string]string{"VMess": vmessURI(`{"v":"2","add":"example.com","port":"443","id":"` + testUUID + `","net":"grpc","path":"svc","mode":"multi","tls":"tls"}`)}, "vmess"},
		{"vmess-xhttp", map[string]string{"VMess": vmessURI(`{"v":"2","add":"example.com","port":"443","id":"` + testUUID + `","net":"xhttp","path":"/x","mode":"stream-up","tls":"tls","extra":"{\"xPaddingBytes\":\"100-1000\"}"}`)}, "vmess"},
		{"vmess-reality", map[string]string{"VMess": vmessURI(`{"v":"2","add":"example.com","port":"443","id":"` + testUUID + `","tls":"reality","sni":"front.example","fp":"chrome","pbk":"` + realityKey + `","sid":"abcd"}`)}, "vmess"},
		{"trojan", map[string]string{"Trojan": "trojan://p%40ss@example.com:443"}, "trojan"},
		{"trojan-ws", map[string]string{"Trojan": "trojan://secret@example.com:443?type=ws&path=%2Fws&host=cdn.example.com&sni=front.example"}, "trojan"},
		{"trojan-grpc", map[string]string{"Trojan": "trojan://secret@example.com:443?type=grpc&serviceName=svc&mode=multi&alpn=h2"}, "trojan"},
		{"naive-h2", map[string]string{"Naive": "naive+https://alice:secret@example.com"}, "naive"},
		{"naive-quic", map[string]string{"Naive": "naive+quic://alice:secret@example.com:8443?sni=front.example"}, "naive"},
		{"hysteria2", map[string]string{"Hysteria2": "hy2://example.com:443?auth=secret&alpn=h3&fp=chrome-146&insecure=0"}, "hysteria2"},
		{"anytls", map[string]string{"AnyTLS": "anytls://secret@example.com?sni=front.example"}, "anytls"},
		{"tuic", map[string]string{"TUIC": "tuic://" + testUUID + ":secret@example.com:443?udp_relay_mode=quic&alpn=h3"}, "tuic"},
		{"ssh", map[string]string{"SSH": "ssh://alice@example.com:2222"}, "ssh"},
		{"ssh-files", map[string]string{"SSH": "ssh://alice@example.com?identity=" + strings.ReplaceAll(ca, `\`, "%5C") + "&known_hosts=%2Fetc%2Fssh%2Fknown_hosts"}, "ssh"},
		{"ssh-option-files", map[string]string{"SSH": "ssh://alice@example.com", "IdentityFile": "~/.ssh/id_ed25519"}, "ssh"},
		{"masque", map[string]string{"MASQUE": "masque://alice:secret@example.com:443?udp_path=%2Fudp%2F%7Btarget_host%7D%2F%7Btarget_port%7D%2F&ca=" + strings.ReplaceAll(ca, `\`, "%5C")}, "masque"},
		{"masque-anonymous", map[string]string{"MASQUE": "masque://example.com"}, "masque"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			original := mustResolve(t, tc.options)
			fields := mustConvert(t, tc.options, true)
			if fields["Type"] != tc.typ {
				t.Fatalf("Type = %q, want %q", fields["Type"], tc.typ)
			}
			for _, source := range uriSources {
				if fields[source] != "" {
					t.Fatalf("explicit options keep source %s", source)
				}
			}
			if tc.options["IdentityFile"] != "" && fields["IdentityFile"] != tc.options["IdentityFile"] {
				t.Fatal("IdentityFile option was not kept")
			}
			uri := mustConvert(t, fields, false)
			// Only the URI source and kept SSH file options remain.
			sources := 0
			for key := range uri {
				if !slices.Contains(keptOptions, key) {
					sources++
				}
			}
			if uri["Type"] != "" || sources != 1 {
				t.Fatalf("URI options = %v", keys(uri))
			}
			if !accesskey.Equivalent(original, mustResolve(t, uri)) {
				t.Fatal("URI round trip changed the profile")
			}
			// fields -> URI -> fields reproduces the same explicit options.
			again := mustConvert(t, uri, true)
			if !accesskey.Equivalent(mustResolve(t, fields), mustResolve(t, again)) {
				t.Fatal("explicit round trip changed the profile")
			}
		})
	}
}

func keys(options map[string]string) []string {
	var result []string
	for key := range options {
		result = append(result, key)
	}
	slices.Sort(result)
	return result
}

// TestAccessConversionExplicitForms covers explicit forms without an
// identical URI spelling: separate XHTTP options, plugins and file options.
func TestAccessConversionExplicitForms(t *testing.T) {
	cases := []struct {
		name    string
		options map[string]string
		field   string
	}{
		{"vless-separate-xhttp", map[string]string{"Type": "vless", "Server": "example.com", "Port": "443", "ID": testUUID, "Encryption": "none", "Network": "xhttp", "Security": "tls", "XHTTPMode": "packet-up", "XHTTPNoGRPCHeader": "true", "XHTTPXPaddingBytes": "100-1000"}, "VLESS"},
		{"vmess-defaults", map[string]string{"Type": "vmess", "Server": "example.com", "Port": "443", "ID": testUUID, "Security": "tls"}, "VMess"},
		{"trojan-no-network", map[string]string{"Type": "trojan", "Server": "example.com", "Port": "443", "Password": "secret"}, "Trojan"},
		{"ss-plugin", map[string]string{"Type": "shadowsocks", "Server": "example.com", "Port": "443", "Method": "aes-128-gcm", "Password": "secret", "Plugin": "obfs-local", "PluginOpts": "obfs=http;obfs-host=cdn.example.com"}, "SS"},
		{"ssh-files", map[string]string{"Type": "ssh", "Server": "example.com", "Port": "22", "Username": "alice", "KnownHostsFile": "~/.ssh/known_hosts"}, "SSH"},
		{"naive-quic", map[string]string{"Type": "naive", "Server": "example.com", "Port": "443", "Username": "alice", "Password": "secret", "Network": "quic"}, "Naive"},
		{"https", map[string]string{"Type": "https", "Server": "example.com", "Port": "443"}, "HTTP"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			uri := mustConvert(t, tc.options, false)
			if uri[tc.field] == "" || uri["Type"] != "" {
				t.Fatalf("URI options = %v", keys(uri))
			}
			if tc.options["KnownHostsFile"] != "" && uri["KnownHostsFile"] != tc.options["KnownHostsFile"] {
				t.Fatal("KnownHostsFile option was not kept")
			}
			fields := mustConvert(t, uri, true)
			if !accesskey.Equivalent(mustResolve(t, tc.options), mustResolve(t, fields)) {
				t.Fatal("round trip changed the profile")
			}
		})
	}
}

func TestAccessConversionRejects(t *testing.T) {
	cases := []struct {
		name     string
		options  map[string]string
		toFields bool
		code     string
		field    string
	}{
		{"ssconf", map[string]string{"SSConf": "ssconf://example.com/key"}, true, "access_conversion_unsupported", "SSConf"},
		{"ssconf-key", map[string]string{"Key": "ssconf://example.com/key"}, false, "access_conversion_unsupported", "Key"},
		{"file", map[string]string{"File": "key.txt"}, true, "access_conversion_unsupported", "File"},
		{"already-fields", map[string]string{"Type": "trojan", "Server": "example.com", "Port": "443", "Password": "secret"}, true, "access_conversion_unsupported", "Type"},
		{"already-uri", map[string]string{"Trojan": "trojan://secret@example.com:443"}, false, "access_conversion_unsupported", "Trojan"},
		{"empty", map[string]string{}, true, "access_conversion_unsupported", ""},
		{"invalid-uri", map[string]string{"Trojan": "trojan://SENTINEL@example.com:443?security=none"}, true, "choice_invalid", "Security"},
		{"invalid-fields", map[string]string{"Type": "hysteria2", "Server": "example.com", "Port": "443", "Password": "SENTINEL", "ALPN": "h2"}, false, "alpn_invalid", "ALPN"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ConvertAccess(tc.options, tc.toFields)
			p, ok := problem.As(err)
			if !ok || p.Code != tc.code || p.Field != tc.field || p.Section != "AccessKey" || p.Line != 0 {
				t.Fatalf("got %#v (%v), want %s at %q", p, err, tc.code, tc.field)
			}
			if strings.Contains(err.Error(), "SENTINEL") || strings.Contains(err.Error(), "example.com") {
				t.Fatalf("error exposes input: %v", err)
			}
		})
	}
}
