package config

import (
	"strings"
	"testing"
)

func TestSSHProfiles(t *testing.T) {
	for _, source := range []string{
		"SSH = ssh://alice@ssh.example.com:22",
		"Key = ssh://alice@ssh.example.com:22?identity=id_ed25519",
		"Type = ssh\nServer = ssh.example.com\nPort = 22\nUsername = alice\nIdentityFile = id_ed25519",
	} {
		for _, mode := range []string{"proxy", "vpn"} {
			b := []byte("[Profile]\nVersion = 1\n[AccessKey]\n" + source + "\n[Interface]\nMode = " + mode + "\n")
			c, err := ParseData(b)
			if err != nil {
				t.Fatal(err)
			}
			p, err := c.Resolve(nil)
			if err != nil || p.Type != "ssh" || p.SSH.User != "alice" {
				t.Fatalf("profile: %+v, %v", p, err)
			}
		}
	}
	for _, source := range []string{
		"SSH = ssh://alice:secret@ssh.example.com:22",
		"SSH = ssh://alice@ssh.example.com:22?identity=a&identity=b",
		"SSH = ssh://alice@ssh.example.com:22?insecure=1",
	} {
		b := []byte("[Profile]\nVersion = 1\n[AccessKey]\n" + source + "\n[Interface]\nMode = proxy\n")
		if _, err := ParseData(b); err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatalf("bad SSH profile accepted or leaked: %v", err)
		}
	}
	if _, err := ParseData([]byte("[Profile]\nVersion = 1\n[AccessKey]\nSSH = ssh://alice@ssh.example.com:22\n")); err != nil {
		t.Fatal("SSH VPN rejected", err)
	}
}
