package accesskey

import (
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
)

func TestSSPluginImport(t *testing.T) {
	base := "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:secret")) + "@[::1]:8388/?plugin="
	for _, tc := range []struct {
		options, host, path string
		mux                 uint32
		tls                 bool
	}{
		{"v2ray-plugin", "cloudfront.com", "/", 1, false},
		{"v2ray-plugin;tls;host=ws.example;path=tunnel;mux=8", "ws.example", "/tunnel", 8, true},
		{`v2ray-plugin;tls=false;path=/a\;b\=c;host=ws.example;mux=0`, "ws.example", "/a;b=c", 0, true},
		{`v2ray-plugin;path=/a%2Fb?q=x%2By;mux=4294967295`, "cloudfront.com", "/a%2Fb?q=x%2By", 4294967295, false},
	} {
		p, err := ParseSS(base + url.QueryEscape(tc.options) + "#Example")
		if err != nil {
			t.Fatal(err)
		}
		s := p.SSPlugin
		if s == nil || s.Host != tc.host || s.Path != tc.path || s.Mux != tc.mux || s.TLS != tc.tls || p.UDP.Host != "" || p.TCP.Host != "::1" || p.Name != "Example" || !p.TCPOnly() {
			t.Fatalf("unexpected imported settings: %+v", s)
		}
	}
	for _, options := range []string{"", "other", "v2ray-plugin;mode=quic", "v2ray-plugin;mux=-1", "v2ray-plugin;mux=+1", "v2ray-plugin;mux=4294967296", "v2ray-plugin;mux=", "v2ray-plugin;tls;tls", "v2ray-plugin;path=/x\\", "v2ray-plugin;;tls", "v2ray-plugin;server", "v2ray-plugin;cert=/private", "v2ray-plugin;host=bad\r\nsecret", "v2ray-plugin;path=//evil", "v2ray-plugin;path=/a#fragment"} {
		_, err := ParseSS(base + url.QueryEscape(options))
		if err == nil {
			t.Fatalf("accepted invalid plugin settings %q", options)
		}
		if strings.Contains(err.Error(), "secret") {
			t.Fatal("options leaked in error")
		}
	}
	for _, raw := range []string{base + "v2ray-plugin&plugin=v2ray-plugin", base + "v2ray-plugin%ZZ"} {
		if _, err := ParseSS(raw); err == nil {
			t.Fatal("accepted malformed query")
		}
	}
}

func TestSSPluginConfigImport(t *testing.T) {
	for _, raw := range []string{
		`{"server":"example.com","server_port":8388,"method":"aes-256-gcm","password":"secret","plugin":"v2ray-plugin","plugin_opts":"tls;host=ws.example;mux=8"}`,
		"server: example.com\nserver_port: 8388\nmethod: aes-256-gcm\npassword: secret\nplugin: v2ray-plugin\nplugin_opts: tls;host=ws.example;mux=8\n",
	} {
		p, err := ParseConfig([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		if p.SSPlugin == nil || p.SSPlugin.Mux != 8 || p.UDP.Host != "" {
			t.Fatal("plugin missing")
		}
	}
	if _, err := ParseConfig([]byte("server: example.com\nserver_port: 8388\nmethod: aes-256-gcm\npassword: secret\nplugin_opts: tls")); err == nil {
		t.Fatal("accepted options without plugin")
	}
}
