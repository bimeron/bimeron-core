package accesskey

import (
	"strings"
	"testing"
)

func TestParseHysteria2(t *testing.T) {
	for _, scheme := range []string{"hysteria2", "hy2"} {
		p, err := ParseHysteria2(scheme + "://s%40cret@[2001:db8::1]:443?sni=example.com#Home")
		if err != nil || p.Type != "hysteria2" || p.Hysteria2.Password != "s@cret" || p.Hysteria2.ServerName != "example.com" || p.TCP.Port != 443 || p.Name != "Home" {
			t.Fatalf("unexpected Hysteria2 profile: %+v, %v", p, err)
		}
	}
	for _, raw := range []string{
		"hy2://secret@example.com:443?insecure=1",
		"hy2://secret@example.com:443?sni=a&sni=b",
		"hy2://secret@example.com:443?obfs=salamander",
		"hy2://secret@example.com:0",
		"hy2://secret@example.com:443?sni=",
	} {
		_, err := ParseHysteria2(raw)
		if err == nil || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), raw) {
			t.Fatalf("expected redacted error for %q: %v", raw, err)
		}
	}
}
