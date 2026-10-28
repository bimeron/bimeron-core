package config

import (
	"context"
	"strings"
	"testing"
)

func TestNaiveSources(t *testing.T) {
	for _, source := range []string{
		"Naive = naive+https://user:pass@example.com\n",
		"Key = naive+https://user:pass@example.com\n",
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
	}
	for _, source := range []string{
		"Naive = naive+https://user:pass@example.com\nKey = naive+https://user:pass@example.com\n",
		"Type = naive\nServer = example.com\nPort = 443\nUsername = user\nPassword = pass\nMethod = aes-256-gcm\n",
		"Type = naive\nServer = example.com\nPort = 443\nUsername = user\nPassword = pass\nPrefix = x\n",
	} {
		_, err := loadText(t, "[Profile]\nVersion = 1\n[AccessKey]\n"+source)
		if err == nil || strings.Contains(err.Error(), "pass") {
			t.Fatalf("unsafe or missing error: %v", err)
		}
	}
}
