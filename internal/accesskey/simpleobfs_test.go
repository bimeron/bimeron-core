package accesskey

import (
	"fmt"
	"net/url"
	"strings"
	"testing"
)

func TestSimpleObfsImport(t *testing.T) {
	for _, tc := range []struct {
		options string
		want    SSPlugin
	}{
		{"obfs=http", SSPlugin{Name: "obfs-local", Mode: "http", Host: "cloudfront.net", Path: "/", Method: "GET"}},
		{"obfs=tls", SSPlugin{Name: "obfs-local", Mode: "tls", Host: "cloudfront.net"}},
		{`obfs=http;obfs-host=cover.example;obfs-uri=/a\;b\=c%2Fd?q=x%2By;http-method=POST`, SSPlugin{Name: "obfs-local", Mode: "http", Host: "cover.example", Path: "/a;b=c%2Fd?q=x%2By", Method: "POST"}},
		{"obfs=tls;obfs-host=cover.example", SSPlugin{Name: "obfs-local", Mode: "tls", Host: "cover.example"}},
	} {
		t.Run(tc.options, func(t *testing.T) {
			p, err := ParseSS("ss://aes-256-gcm:secret@server.example:8388/?plugin=" + url.QueryEscape("obfs-local;"+tc.options) + "#Example")
			if err != nil {
				t.Fatal(err)
			}
			if p.SSPlugin == nil || *p.SSPlugin != tc.want || p.TCP.Host != "server.example" || p.Name != "Example" || p.UDP != (Endpoint{}) || !p.TCPOnly() {
				t.Fatalf("unexpected profile: plugin=%+v", p.SSPlugin)
			}
		})
	}
}

func TestSimpleObfsRejectsInvalidOptions(t *testing.T) {
	for _, options := range []string{
		"", "obfs", "obfs=", "obfs=quic", "obfs=HTTP", "obfs=http;obfs=tls",
		"obfs=http;obfs-host", "obfs=http;obfs-host=", "obfs=http;obfs-host=bad\r\nsecret",
		"obfs=http;obfs-host=cover.example:80", "obfs=http;obfs-host=cover.example;obfs-host=other.example",
		"obfs=http;obfs-uri", "obfs=http;obfs-uri=", "obfs=http;obfs-uri=relative",
		"obfs=http;obfs-uri=//other.example", "obfs=http;obfs-uri=/a#secret",
		"obfs=http;obfs-uri=/a b", "obfs=http;obfs-uri=/a\tsecret", "obfs=http;obfs-uri=/a\x00secret",
		"obfs=http;obfs-uri=/a%ZZ", "obfs=http;obfs-uri=/" + strings.Repeat("a", 4096),
		"obfs=http;http-method", "obfs=http;http-method=", "obfs=http;http-method=GET secret",
		"obfs=http;http-method=GET\r\nsecret", "obfs=tls;obfs-uri=/", "obfs=tls;http-method=GET",
		"obfs=http;tls", "obfs=http;mode=websocket", "obfs=http;mux=0", "obfs=http;path=/",
		"obfs=http;host=cover.example", "obfs=http;fast-open", "obfs=http;unknown=secret",
		"obfs=http;;obfs-host=cover.example", "obfs=http;obfs-uri=/x\\",
	} {
		t.Run(options, func(t *testing.T) {
			_, err := ParseSS("ss://aes-256-gcm:secret@server.example:8388/?plugin=" + url.QueryEscape("obfs-local;"+options))
			if err == nil {
				t.Fatal("accepted invalid simple-obfs options")
			}
			if strings.Contains(err.Error(), "secret") {
				t.Fatal("error leaked credentials or options")
			}
		})
	}
	for _, name := range []string{"simple-obfs", "obfs-server", "/usr/bin/obfs-local", `C:\bin\obfs-local.exe`} {
		if _, err := ParseSSPlugin(name, "obfs=http"); err == nil {
			t.Fatalf("accepted plugin identifier %q", name)
		}
	}
	for _, options := range []string{"obfs=http", "obfs-host=cover.example", "obfs-uri=/", "http-method=GET"} {
		if _, err := ParseSSPlugin("v2ray-plugin", options); err == nil {
			t.Fatal("accepted simple-obfs options for v2ray-plugin")
		}
	}
	if _, err := ParseSS("ss://aes-256-gcm:secret@server.example:8388/?plugin=obfs-local%3Bobfs%3Dhttp&plugin=obfs-local%3Bobfs%3Dtls"); err == nil {
		t.Fatal("accepted duplicate plugin query")
	}
}

func TestSimpleObfsConfigImport(t *testing.T) {
	for _, options := range []string{"obfs=http;obfs-host=cover.example;obfs-uri=/a%2Fb?q=x%2By;http-method=POST", `obfs=http;obfs-uri=/a\;b\=c`, "obfs=tls;obfs-host=cover.example"} {
		want, err := ParseSS("ss://aes-256-gcm:secret@server.example:8388/?plugin=" + url.QueryEscape("obfs-local;"+options))
		if err != nil {
			t.Fatal(err)
		}
		for _, raw := range []string{
			fmt.Sprintf(`{"server":"server.example","server_port":8388,"method":"aes-256-gcm","password":"secret","plugin":"obfs-local","plugin_opts":%q}`, options),
			"server: server.example\nserver_port: 8388\nmethod: aes-256-gcm\npassword: secret\nplugin: obfs-local\nplugin_opts: " + options + "\n",
		} {
			got, err := ParseConfig([]byte(raw))
			if err != nil {
				t.Fatal(err)
			}
			if got.SSPlugin == nil || *got.SSPlugin != *want.SSPlugin || got.TCP != want.TCP || got.UDP != (Endpoint{}) || !got.TCPOnly() {
				t.Fatal("configuration differs from URI import")
			}
		}
	}
}

func TestSimpleObfsDirectSettingsValidation(t *testing.T) {
	valid := SSPlugin{Name: "obfs-local", Mode: "http", Host: "cover.example", Path: "/", Method: "GET"}
	for _, change := range []func(*SSPlugin){
		func(p *SSPlugin) { p.Name = "unknown" },
		func(p *SSPlugin) { p.Mode = "" },
		func(p *SSPlugin) { p.Mode = "tls" },
		func(p *SSPlugin) { p.TLS = true },
		func(p *SSPlugin) { p.Mux = 1 },
		func(p *SSPlugin) { p.Method = "" },
		func(p *SSPlugin) { p.Method = "GET secret" },
		func(p *SSPlugin) { p.Path = "" },
		func(p *SSPlugin) { p.Host = "" },
		func(p *SSPlugin) { p.Name = "v2ray-plugin" },
		func(p *SSPlugin) { p.Name = "" },
	} {
		p := valid
		change(&p)
		if err := p.Validate(); err == nil {
			t.Fatalf("accepted contradictory settings: %+v", p)
		}
	}
	for _, p := range []SSPlugin{valid, {Name: "obfs-local", Mode: "tls", Host: "cover.example"}, {Host: "cloudfront.com", Path: "/", Mux: 1}, {Name: "v2ray-plugin", Host: "cloudfront.com", Path: "/", Mux: 1}} {
		if err := p.Validate(); err != nil {
			t.Fatal(err)
		}
	}
}
