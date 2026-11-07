package accesskey

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"bimeron/internal/problem"
)

type wantProblem struct {
	code, section, field string
	related              []string
	value                problem.Value
	args                 map[string]string
}

func checkProblem(t *testing.T, name string, err error, want wantProblem) {
	t.Helper()
	p, ok := problem.As(err)
	if !ok {
		t.Fatalf("%s: uncoded error %v", name, err)
	}
	if !problem.Known(p.Code) {
		t.Fatalf("%s: code %q is not in the catalog", name, p.Code)
	}
	if p.Code != want.code || p.Section != want.section || p.Field != want.field || strings.Join(p.Related, ",") != strings.Join(want.related, ",") || p.Value != want.value {
		t.Fatalf("%s: problem = %+v, want %+v", name, p, want)
	}
	for k, v := range want.args {
		if p.Args[k] != v {
			t.Fatalf("%s: arg %s = %q, want %q", name, k, p.Args[k], v)
		}
	}
	data, _ := json.Marshal(p)
	if strings.Contains(string(data), "Sentinel7secret") {
		t.Fatalf("%s: problem leaked a secret: %s", name, data)
	}
}

func errOf(_ Profile, err error) error { return err }

func TestVMessProblems(t *testing.T) {
	base := `{"v":"2","add":"example.com","port":"443","id":"123e4567-e89b-12d3-a456-426614174000","aid":"0","scy":"auto","net":"ws","path":"/vpn","tls":"tls","sni":"example.com"}`
	xhttp := strings.Replace(strings.Replace(base, `"net":"ws"`, `"net":"xhttp"`, 1), `"tls":"tls"`, `"tls":"tls","mode":"stream-up"`, 1)
	for _, tc := range []struct {
		name, json string
		want       wantProblem
	}{
		{"alter id", strings.Replace(base, `"aid":"0"`, `"aid":"64"`, 1), wantProblem{code: "vmess_legacy_unsupported", field: "AlterID"}},
		{"version", strings.Replace(base, `"v":"2"`, `"v":"1"`, 1), wantProblem{code: "vmess_legacy_unsupported", field: "VMessVersion"}},
		{"cipher", strings.Replace(base, `"scy":"auto"`, `"scy":"none"`, 1), wantProblem{code: "choice_invalid", field: "VMessSecurity", args: map[string]string{"allowed": "auto, aes-128-gcm, chacha20-poly1305"}}},
		{"user id", strings.Replace(base, `"id":"123e4567-e89b-12d3-a456-426614174000"`, `"id":"Sentinel7secret"`, 1), wantProblem{code: "uuid_invalid", field: "ID", value: problem.Present}},
		{"port", strings.Replace(base, `"port":"443"`, `"port":"x"`, 1), wantProblem{code: "port_invalid", field: "Port"}},
		{"transport", strings.Replace(base, `"net":"ws"`, `"net":"kcp"`, 1), wantProblem{code: "choice_invalid", field: "VMessNetwork"}},
		{"ws path", strings.Replace(base, `"path":"/vpn"`, `"path":"https://x"`, 1), wantProblem{code: "path_invalid", field: "VMessPath"}},
		{"ws alpn", strings.Replace(base, `"sni":"example.com"`, `"sni":"example.com","alpn":"h2"`, 1), wantProblem{code: "alpn_invalid", field: "ALPN", related: []string{"VMessNetwork"}, args: map[string]string{"allowed": "http/1.1"}}},
		{"unknown field", strings.Replace(base, `"v":"2"`, `"v":"2","evil":"x"`, 1), wantProblem{code: "uri_option_unsupported"}},
		{"extra json", strings.Replace(xhttp, `"net":"xhttp"`, `"net":"xhttp","extra":"{\"evil\":true}"`, 1), wantProblem{code: "xhttp_extra_invalid", field: "VMessExtra"}},
		{"extra mode", strings.Replace(xhttp, `"net":"xhttp"`, `"net":"xhttp","extra":"{\"uplinkHTTPMethod\":\"GET\"}"`, 1), wantProblem{code: "option_requires_mode", field: "VMessExtra", related: []string{"VMessMode"}, args: map[string]string{"mode": "packet-up"}}},
		{"extra without xhttp", strings.Replace(base, `"net":"ws"`, `"net":"ws","extra":"{}"`, 1), wantProblem{code: "option_requires_transport", field: "VMessExtra", related: []string{"VMessNetwork"}}},
		{"reality without fingerprint", strings.Replace(strings.Replace(base, `"net":"ws"`, `"net":"tcp"`, 1), `"tls":"tls"`, `"tls":"reality"`, 1), wantProblem{code: "value_required", field: "Fingerprint", value: problem.Absent}},
	} {
		_, err := ParseVMess(vmessLink(tc.json))
		checkProblem(t, tc.name, err, tc.want)
	}
	if _, err := ParseVMess("vmess://%%%"); err == nil {
		t.Fatal("accepted malformed VMess URI")
	} else {
		checkProblem(t, "uri", err, wantProblem{code: "uri_invalid"})
	}
}

func TestXHTTPProblemFields(t *testing.T) {
	extra, err := ParseXHTTPExtra(`{"xPaddingBytes":2000000}`)
	if err != nil {
		t.Fatal(err)
	}
	checkProblem(t, "extra range", extra.Validate("auto", "tls", "h2"), wantProblem{code: "xhttp_range_invalid", field: "XHTTPExtra", args: map[string]string{"min": "1", "max": "1048576"}})
	separate := &XHTTPOptions{}
	if err := separate.SetXHTTPConfField("XHTTPXPaddingBytes", "2000000"); err != nil {
		t.Fatal(err)
	}
	checkProblem(t, "separate range", separate.Validate("auto", "tls", "h2"), wantProblem{code: "xhttp_range_invalid", field: "XHTTPXPaddingBytes"})
	checkProblem(t, "boolean", separate.SetXHTTPConfField("XHTTPNoGRPCHeader", "yes"), wantProblem{code: "boolean_invalid", field: "XHTTPNoGRPCHeader"})
	checkProblem(t, "unknown", separate.SetXHTTPConfField("XHTTPBogus", "1"), wantProblem{code: "option_unknown", field: "XHTTPBogus"})
	checkProblem(t, "separate json", separate.SetXHTTPConfField("XHTTPXmux", "{"), wantProblem{code: "xhttp_extra_invalid", field: "XHTTPXmux"})
	_, err = ParseXHTTPExtra(strings.Repeat(" ", 16*1024+1))
	checkProblem(t, "too large", err, wantProblem{code: "value_too_long", field: "XHTTPExtra", args: map[string]string{"max": "16384"}})
	download, err := ParseXHTTPExtra(`{"downloadSettings":{"address":"d.example","port":443,"network":"xhttp","security":"tls","tlsSettings":{"fingerprint":"bogus"}}}`)
	if err != nil {
		t.Fatal(err)
	}
	checkProblem(t, "download fingerprint", download.Validate("packet-up", "tls", "h2"), wantProblem{code: "fingerprint_unsupported", field: "XHTTPExtra"})
	checkProblem(t, "download stream-one", download.Validate("stream-one", "tls", "h2"), wantProblem{code: "combination_unsupported", field: "XHTTPExtra", related: []string{"XHTTPMode"}})
}

func TestTUICNaiveMASQUEProblems(t *testing.T) {
	const id = "123e4567-e89b-12d3-a456-426614174000"
	for _, tc := range []struct {
		name string
		err  error
		want wantProblem
	}{
		{"tuic relay", errOf(ParseTUIC("tuic://" + id + ":Sentinel7secret@example.com:443?udp_relay_mode=native")), wantProblem{code: "choice_invalid", field: "UDPRelayMode", args: map[string]string{"allowed": "quic"}}},
		{"tuic id", errOf(ParseTUIC("tuic://bad:Sentinel7secret@example.com:443")), wantProblem{code: "uuid_invalid", field: "ID", value: problem.Present}},
		{"tuic password", errOf(ParseTUIC("tuic://" + id + "@example.com:443")), wantProblem{code: "value_required", field: "Password", value: problem.Absent}},
		{"tuic port", errOf(ParseTUIC("tuic://" + id + ":Sentinel7secret@example.com:0")), wantProblem{code: "port_invalid", field: "Port"}},
		{"tuic option", errOf(ParseTUIC("tuic://" + id + ":Sentinel7secret@example.com:443?x=1")), wantProblem{code: "uri_option_unsupported"}},
		{"naive password", errOf(ParseNaive("naive+https://alice@example.com")), wantProblem{code: "value_required", field: "Password", value: problem.Absent}},
		{"naive user", Naive{User: "a:b", Password: "Sentinel7secret", ServerName: "example.com"}.Validate("example.com", 443), wantProblem{code: "value_has_invalid_characters", field: "Username"}},
		{"naive server name", errOf(ParseNaive("naive+https://alice:Sentinel7secret@example.com?sni=a%20b")), wantProblem{code: "server_name_invalid", field: "ServerName"}},
		{"masque path", errOf(ParseMASQUE("masque://proxy.example?udp_path=%2Fudp%2F")), wantProblem{code: "masque_path_invalid", field: "MASQUEPath", args: map[string]string{"host_variable": "{target_host}", "port_variable": "{target_port}"}}},
		{"masque ca", errOf(ParseMASQUE("masque://proxy.example?ca=ca.pem")), wantProblem{code: "path_must_be_absolute", field: "CAFile"}},
		{"masque credentials", MASQUE{ServerName: "proxy.example"}.Validate("proxy.example", 443, "alice", ""), wantProblem{code: "credentials_incomplete", field: "Password", related: []string{"Username"}, value: problem.Absent}},
		{"masque endpoint", MASQUE{ServerName: "proxy.example"}.Validate("a b", 443, "", ""), wantProblem{code: "host_invalid", field: "Server"}},
	} {
		checkProblem(t, tc.name, tc.err, tc.want)
	}
}

func TestPluginAndShadowTLSProblems(t *testing.T) {
	ss := "ss://aes-256-gcm:Sentinel7secret@example.com:8388/?plugin="
	for _, tc := range []struct {
		name, plugin string
		want         wantProblem
	}{
		{"plugin name", "other", wantProblem{code: "choice_invalid", field: "Plugin", args: map[string]string{"allowed": "v2ray-plugin, obfs-local"}}},
		{"plugin empty", ";tls", wantProblem{code: "value_required", field: "Plugin", value: problem.Absent}},
		{"obfs option", "obfs-local;obfs=http;unknown=Sentinel7secret", wantProblem{code: "plugin_option_unsupported", field: "PluginOpts", value: problem.Present}},
		{"obfs missing value", "obfs-local;obfs=http;obfs-host", wantProblem{code: "plugin_options_invalid", field: "PluginOpts", value: problem.Present}},
		{"obfs mode", "obfs-local;obfs-host=cover.example", wantProblem{code: "plugin_option_invalid", field: "PluginOpts", value: problem.Present, args: map[string]string{"option": "obfs"}}},
		{"obfs tls uri", "obfs-local;obfs=tls;obfs-uri=/", wantProblem{code: "option_requires_mode", field: "PluginOpts", value: problem.Present}},
		{"v2ray mux", "v2ray-plugin;mux=x", wantProblem{code: "plugin_option_invalid", field: "PluginOpts", value: problem.Present, args: map[string]string{"option": "mux"}}},
		{"v2ray host", "v2ray-plugin;host=a b", wantProblem{code: "plugin_option_invalid", field: "PluginOpts", value: problem.Present, args: map[string]string{"option": "host"}}},
	} {
		_, err := ParseSS(ss + url.QueryEscape(tc.plugin))
		checkProblem(t, tc.name, err, tc.want)
	}

	checkProblem(t, "shadowtls name", ShadowTLS{ServerName: "-bad", Password: "Sentinel7secret"}.Validate(), wantProblem{code: "server_name_invalid", section: "ShadowTLS", field: "ServerName"})
	checkProblem(t, "shadowtls password", ShadowTLS{ServerName: "cover.example"}.Validate(), wantProblem{code: "value_required", section: "ShadowTLS", field: "Password", value: problem.Absent})
	wrapper := &ShadowTLS{ServerName: "cover.example", Password: "Sentinel7secret"}
	endpoint := Endpoint{Host: "example.com", Port: 443, Cipher: "aes-256-gcm", Secret: "Sentinel7secret"}
	plugin := Profile{TCP: endpoint, SSPlugin: &SSPlugin{Host: "cloudfront.com", Path: "/", Mux: 1}, ShadowTLS: wrapper}
	checkProblem(t, "shadowtls plugin", plugin.ValidateShadowTLS(), wantProblem{code: "shadowtls_plugin_unsupported"})
	naive := Profile{Type: "naive", TCP: Endpoint{Host: "example.com", Port: 443}, Naive: Naive{User: "a", Password: "Sentinel7secret", ServerName: "example.com", QUIC: true}, ShadowTLS: wrapper}
	checkProblem(t, "shadowtls http3", naive.ValidateShadowTLS(), wantProblem{code: "shadowtls_http3_unsupported"})
	socks := Profile{Type: "socks5", TCP: Endpoint{Host: "example.com", Port: 1080}, ShadowTLS: wrapper}
	checkProblem(t, "shadowtls upstream", socks.ValidateShadowTLS(), wantProblem{code: "shadowtls_upstream_unsupported"})
	key := base64.StdEncoding.EncodeToString([]byte("aes-192-gcm:Sentinel7secret"))
	cipher, err := ParseSS("ss://" + key + "@example.com:8388")
	if err != nil {
		t.Fatal(err)
	}
	cipher.ShadowTLS = wrapper
	checkProblem(t, "shadowtls cipher", cipher.ValidateShadowTLS(), wantProblem{code: "shadowtls_cipher_unsupported"})
}
