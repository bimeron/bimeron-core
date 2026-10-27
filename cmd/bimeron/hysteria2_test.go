package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateHysteria2Fingerprint(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fixture.conf")
	for _, fp := range []string{"firefox", "firefox-116", "firefox-116b", "firefox-116c", "chrome", "fixture-invalid"} {
		content := "[Profile]\nVersion=1\n[AccessKey]\nHysteria2=hysteria2://host.example:8449?auth=fixture-pass&sni=name.example&insecure=0&alpn=h3&fp=" + fp + "#label\n"
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		err := validateConfig([]string{path})
		if fp == "fixture-invalid" {
			if err == nil {
				t.Fatal("invalid fingerprint accepted")
			}
			if strings.Contains(err.Error(), "fixture-pass") || strings.Contains(err.Error(), "hysteria2://") {
				t.Fatal("secret in validation error")
			}
		} else if err != nil {
			t.Fatal(err)
		}
	}
}
