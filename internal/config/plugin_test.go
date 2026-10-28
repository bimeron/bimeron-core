package config

import (
	"context"
	"net/url"
	"strings"
	"testing"
)

func TestExplicitShadowsocksPlugin(t *testing.T) {
	base := "[Profile]\nVersion = 1\n[AccessKey]\nType = shadowsocks\nServer = example.com\nPort = 443\nMethod = aes-256-gcm\nPassword = secret\n"
	c, err := ParseData([]byte(base + "Plugin = v2ray-plugin\nPluginOpts = tls;host=ws.example;path=/ws;mux=8\n"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := c.Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if p.SSPlugin == nil || p.SSPlugin.Mux != 8 || !p.SSPlugin.TLS || p.UDP.Host != "" {
		t.Fatal("plugin was not preserved")
	}
	for _, raw := range []string{
		base + "PluginOpts = tls\n",
		base + "Plugin = unknown\n",
		base + "Plugin = v2ray-plugin\n[ShadowTLS]\nServerName = handshake.example\nPassword = outer-secret\n",
		base + "Plugin = v2ray-plugin\nPluginOpts = tls;unknown=secret\n",
		strings.Replace(base, "Type = shadowsocks", "Type = socks5", 1) + "Plugin = v2ray-plugin\n",
		"[Profile]\nVersion = 1\n[AccessKey]\nSS = ss://aes-256-gcm:secret@example.com:443\nPlugin = v2ray-plugin\n",
	} {
		if _, err := ParseData([]byte(raw)); err == nil {
			t.Fatal("accepted invalid or mixed plugin configuration")
		}
	}
}

func TestExplicitSimpleObfsPlugin(t *testing.T) {
	base := "[Profile]\nVersion = 1\n[AccessKey]\nType = shadowsocks\nServer = server.example\nPort = 8388\nMethod = aes-256-gcm\nPassword = secret\n"
	for _, options := range []string{"obfs=http", "obfs=tls", "obfs=http;obfs-host=cover.example;obfs-uri=/a%2Fb?q=x%2By;http-method=POST"} {
		explicit, err := ParseData([]byte(base + "Plugin = obfs-local\nPluginOpts = " + options + "\n"))
		if err != nil {
			t.Fatal(err)
		}
		uri, err := ParseData([]byte("[Profile]\nVersion = 1\n[AccessKey]\nSS = ss://aes-256-gcm:secret@server.example:8388/?plugin=" + url.QueryEscape("obfs-local;"+options) + "\n"))
		if err != nil {
			t.Fatal(err)
		}
		p, err := explicit.Resolve(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		want, err := uri.Resolve(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if p.SSPlugin == nil || want.SSPlugin == nil || *p.SSPlugin != *want.SSPlugin || p.TCP != want.TCP || p.UDP.Host != "" || !p.TCPOnly() {
			t.Fatal("explicit simple-obfs configuration differs from URI import")
		}
	}
	for _, raw := range []string{
		base + "Plugin = obfs-local\n",
		base + "Plugin = obfs-local\nPluginOpts = obfs=tls;obfs-uri=/\n",
		base + "Plugin = obfs-local\nPluginOpts = obfs=http;unknown=secret\n",
		base + "Plugin = obfs-local\nPluginOpts = obfs=http\n[ShadowTLS]\nServerName = handshake.example\nPassword = outer-secret\n",
		strings.Replace(base, "Type = shadowsocks", "Type = socks5", 1) + "Plugin = obfs-local\nPluginOpts = obfs=http\n",
		"[Profile]\nVersion = 1\n[AccessKey]\nSS = ss://aes-256-gcm:secret@server.example:8388\nPlugin = obfs-local\nPluginOpts = obfs=http\n",
	} {
		if _, err := ParseData([]byte(raw)); err == nil {
			t.Fatal("accepted invalid or mixed simple-obfs configuration")
		} else if strings.Contains(err.Error(), "secret") {
			t.Fatal("error leaked credentials or options")
		}
	}
}
