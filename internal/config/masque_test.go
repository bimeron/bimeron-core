package config

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMASQUESources(t *testing.T) {
	base := "[Profile]\nVersion = 1\n[AccessKey]\n"
	for _, source := range []string{
		"MASQUE = masque://user:secret@proxy.example:8443?sni=tls.example",
		"Key = masque://user:secret@proxy.example:8443?sni=tls.example",
		"Type = masque\nServer = proxy.example\nPort = 8443\nServerName = tls.example\nUsername = user\nPassword = secret",
	} {
		c, err := loadText(t, base+source+"\n")
		if err != nil {
			t.Fatal(err)
		}
		p, err := c.Resolve(context.Background())
		if err != nil || p.Type != "masque" || p.MASQUE.ServerName != "tls.example" || p.Username != "user" || p.TCP.Secret != "secret" || p.TCP != p.UDP {
			t.Fatalf("profile: %v", err)
		}
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "key.txt"), []byte("masque://proxy.example:443"), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "profile.conf")
	if err := os.WriteFile(path, []byte(base+"File = key.txt\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if c, err := Load(path); err != nil {
		t.Fatal(err)
	} else if p, err := c.Resolve(context.Background()); err != nil || p.Type != "masque" {
		t.Fatal(err)
	}
	c, err := loadText(t, base+"Type = masque\nServer = proxy.example\nPort = 443\nCAFile = ca.pem\nMASQUEPath = /custom/{target_host}/{target_port}/\n")
	if err != nil {
		t.Fatal(err)
	}
	p, err := c.Resolve(context.Background())
	if err != nil || !filepath.IsAbs(p.MASQUE.CAFile) || p.MASQUE.UDPPath != "/custom/{target_host}/{target_port}/" {
		t.Fatal(err)
	}
	for _, source := range []string{
		"MASQUE = https://proxy.example", "MASQUE = masque://proxy.example\nHTTP = http://proxy.example:8080",
		"Type = masque\nServer = proxy.example\nPort = 443\nUsername = user",
		"Type = masque\nServer = proxy.example\nPort = 443\nMethod = aes-256-gcm",
		"Type = http\nServer = proxy.example\nPort = 443\nMASQUEPath = /x/{target_host}/{target_port}/",
		"Type = masque\nServer = proxy.example\nPort = 443\nMASQUEPath = //evil/{target_host}/{target_port}/",
	} {
		if _, err := loadText(t, base+source+"\n"); err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatalf("invalid source: %v", err)
		}
	}
	if _, err := ParseData([]byte(base + "Type = masque\nServer = proxy.example\nPort = 443\nCAFile = relative.pem\n")); err == nil {
		t.Fatal("relative in-memory CA accepted")
	}
}
