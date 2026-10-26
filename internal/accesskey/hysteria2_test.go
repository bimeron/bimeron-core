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
	query := "hysteria2://server.example:8449?auth=fixture-pass&sni=sni.example&insecure=0&alpn=h3#Profile"
	p, err := ParseHysteria2(query)
	if err != nil || p.Hysteria2.Password != "fixture-pass" || p.Hysteria2.ServerName != "sni.example" || p.Hysteria2.ALPN != "h3" || p.TCP.Port != 8449 || p.Name != "Profile" {
		t.Fatalf("unexpected query-auth profile: %v", err)
	}
	for _, raw := range []string{
		"hy2://fixture-pass@example.com:443?insecure=1",
		"hy2://fixture-pass@example.com:443?auth=other",
		"hy2://example.com:443?auth=fixture-pass&auth=other",
		"hy2://example.com:443?auth=fixture-pass&alpn=h2",
		"hy2://example.com:443?auth=fixture-pass&fp=firefox",
		"hy2://example.com:443?auth=fixture-pass&insecure=true",
		"hy2://secret@example.com:443?sni=a&sni=b",
		"hy2://secret@example.com:443?obfs=salamander",
		"hy2://secret@example.com:0",
		"hy2://secret@example.com:443?sni=",
	} {
		_, err := ParseHysteria2(raw)
		if err == nil || strings.Contains(err.Error(), "fixture-pass") || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), raw) {
			t.Fatalf("expected redacted error for %q: %v", raw, err)
		}
	}
	if _, err := ParseHysteria2("hy2://example.com:443?auth=fixture-pass&fp=firefox"); err == nil || !strings.Contains(err.Error(), "Firefox") {
		t.Fatalf("expected explicit Firefox limitation, got %v", err)
	}
	if err := (Hysteria2{Password: "fixture-pass", ServerName: "example.com", ALPN: "h2"}).Validate("example.com", 443); err == nil {
		t.Fatal("unsupported ALPN was accepted")
	}
}
