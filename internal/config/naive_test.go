package config

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNaiveSources(t *testing.T) {
	for _, source := range []string{
		"Naive = naive+https://user:pass@example.com\n",
		"Key = naive+https://user:pass@example.com\n",
		"Naive = naive+quic://user:pass@example.com\n",
		"Key = naive+quic://user:pass@example.com\n",
		"Type = naive\nServer = example.com\nPort = 443\nUsername = user\nPassword = pass\nServerName = example.com\n",
	} {
		c, err := loadText(t, "[Profile]\nVersion = 1\n[AccessKey]\n"+source)
		if err != nil {
			t.Fatal(err)
		}
		p, err := c.Resolve(context.Background())
		if err != nil || p.Type != "naive" || p.Naive.User != "user" || p.Naive.Password != "pass" {
			t.Fatalf("source %q: %+v, %v", source, p, err)
		}
		if p.Naive.QUIC != strings.Contains(source, "naive+quic://") {
			t.Fatal("NaiveProxy transport selection lost")
		}
	}
	for _, source := range []string{
		"Naive = naive+https://user:pass@example.com\nKey = naive+https://user:pass@example.com\n",
		"Type = naive\nServer = example.com\nPort = 443\nUsername = user\nPassword = pass\nMethod = aes-256-gcm\n",
		"Type = naive\nServer = example.com\nPort = 443\nUsername = user\nPassword = pass\nPrefix = x\n",
		"Naive = naive+quic://user:pass@example.com\n[ShadowTLS]\nServerName = cover.example\nPassword = wrapper-secret\n",
	} {
		_, err := loadText(t, "[Profile]\nVersion = 1\n[AccessKey]\n"+source)
		if err == nil || strings.Contains(err.Error(), "pass") {
			t.Fatalf("unsafe or missing error: %v", err)
		}
	}
}

func TestNaiveQUICKeyFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "access.key"), []byte("naive+quic://user:pass@example.com?sni=proxy.example"), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "profile.conf")
	if err := os.WriteFile(path, []byte("[Profile]\nVersion = 1\n[AccessKey]\nFile = access.key\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	p, err := c.Resolve(t.Context())
	if err != nil || !p.Naive.QUIC || p.Naive.ServerName != "proxy.example" {
		t.Fatalf("HTTP/3 key file: %v", err)
	}
}
