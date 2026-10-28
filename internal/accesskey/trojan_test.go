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
		"trojan://secret@example.com:443?type=grpc",
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

func TestTrojanTransports(t *testing.T) {
	for _, query := range []string{"type=ws", "type=ws&path=%2Fproxy&host=front.example.com&alpn=http%2F1.1", "type=grpc&serviceName=proxy&authority=front.example.com&alpn=h2", "type=grpc&serviceName=proxy&mode=multi"} {
		p, err := ParseTrojan("trojan://secret@example.com:443?" + query)
		if err != nil {
			t.Fatalf("%s: %v", query, err)
		}
		if p.Trojan.Network == "" {
			t.Fatal("missing network")
		}
	}
	for _, query := range []string{"type=ws&alpn=h2", "type=grpc&serviceName=proxy&alpn=http%2F1.1", "type=tcp&path=", "type=ws&serviceName=", "type=grpc&serviceName=proxy&mode=auto", "type=ws&path=%2Fproxy%3Fed%3D2048", "type=ws&ed=2048", "type=ws&host=bad%0Ahost", "type=ws&path=%2Fbad%0Apath", "type=grpc&serviceName=bad%2Fservice", "type=ws&type=grpc", "type=grpc&serviceName=proxy&authority=bad%2Fhost", "type=xhttp", "type="} {
		_, err := ParseTrojan("trojan://secret@example.com:443?" + query)
		if err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatalf("unsafe or missing error for %s: %v", query, err)
		}
	}
}
