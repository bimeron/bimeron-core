package accesskey

import (
	"strings"
	"testing"
)

func TestParseTrojan(t *testing.T) {
	p, err := ParseTrojan("trojan://s%40cret@[2001:db8::1]:443?security=tls&type=tcp&sni=example.com#Home")
	if err != nil || p.Type != "trojan" || p.Trojan.Password != "s@cret" || p.Trojan.ServerName != "example.com" || p.TCP.Port != 443 || p.Name != "Home" {
		t.Fatalf("unexpected Trojan profile: %+v, %v", p, err)
	}
	for _, uri := range []string{
		"trojan://secret@example.com:443?type=ws",
		"trojan://secret@example.com:443?security=none",
		"trojan://secret@example.com:443?fp=chrome",
		"trojan://secret@example.com:443?sni=a&sni=b",
		"trojan://secret@example.com:0",
		"trojan://secret@example.com:443?sni=",
	} {
		_, err := ParseTrojan(uri)
		if err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatalf("unsafe or missing error for %q: %v", uri, err)
		}
	}
}
