package config

import (
	"context"
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
		base + "Plugin = v2ray-plugin\nPluginOpts = tls;unknown=secret\n",
		strings.Replace(base, "Type = shadowsocks", "Type = socks5", 1) + "Plugin = v2ray-plugin\n",
		"[Profile]\nVersion = 1\n[AccessKey]\nSS = ss://aes-256-gcm:secret@example.com:443\nPlugin = v2ray-plugin\n",
	} {
		if _, err := ParseData([]byte(raw)); err == nil {
			t.Fatal("accepted invalid or mixed plugin configuration")
		}
	}
}
