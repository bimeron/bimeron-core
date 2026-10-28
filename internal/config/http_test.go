package config

import (
	"context"
	"strings"
	"testing"
)

func TestHTTPConnectSources(t *testing.T) {
	base := "[Profile]\nVersion = 1\n[AccessKey]\n"
	for _, source := range []string{
		"HTTP = http://alice:secret@proxy.example.com:8080",
		"Key = http://alice:secret@proxy.example.com:8080",
		"Type = http\nServer = proxy.example.com\nPort = 8080\nUsername = alice\nPassword = secret",
	} {
		c, err := loadText(t, base+source+"\n")
		if err != nil {
			t.Fatal(err)
		}
		p, err := c.Resolve(context.Background())
		if err != nil || p.Type != "http" || p.Username != "alice" || p.TCP.Secret != "secret" || p.UDP.Host != "" {
			t.Fatalf("invalid HTTP profile: %v", err)
		}
	}
	for _, source := range []string{
		"HTTP = https://proxy.example.com:443",
		"HTTP = http://proxy.example.com:8080/path",
		"HTTP = http://alice:secret@proxy.example.com:8080\nSOCKS5 = socks5://proxy.example.com:1080",
		"Type = http\nServer = proxy.example.com\nPort = 8080\nUsername = alice",
		"Type = http\nServer = proxy.example.com\nPort = 8080\nMethod = aes-256-gcm",
	} {
		if _, err := loadText(t, base+source+"\n"); err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatalf("invalid source: %s, %v", source, err)
		}
	}
}
