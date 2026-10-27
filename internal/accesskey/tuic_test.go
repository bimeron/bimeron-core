package accesskey

import (
	"strings"
	"testing"
)

func TestParseTUIC(t *testing.T) {
	key := "tuic://123e4567-e89b-12d3-a456-426614174000:secret@example.com:443?sni=front.example&alpn=h3&udp_relay_mode=quic#Test"
	p, err := ParseTUIC(key)
	if err != nil || p.Type != "tuic" || p.TUIC.ServerName != "front.example" || p.TUIC.ALPN != "h3" || p.Name != "Test" {
		t.Fatalf("TUIC profile: %+v, %v", p, err)
	}
	for _, bad := range []string{
		"tuic://bad:secret@example.com:443",
		"tuic://123e4567-e89b-12d3-a456-426614174000@example.com:443",
		"tuic://123e4567-e89b-12d3-a456-426614174000:secret@example.com:443?udp_relay_mode=native",
		"tuic://123e4567-e89b-12d3-a456-426614174000:secret@example.com:443?alpn=h3&alpn=foo",
		"tuic://123e4567-e89b-12d3-a456-426614174000:secret@example.com:443?insecure=1",
	} {
		_, err := ParseTUIC(bad)
		if err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatalf("unsafe acceptance or error for %q: %v", bad, err)
		}
	}
}
