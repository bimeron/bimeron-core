package accesskey

import (
	"strings"
	"testing"
)

func TestHTTPConnectURI(t *testing.T) {
	for _, uri := range []string{
		"http://proxy.example.com:8080",
		"https://proxy.example.com:443",
		"https://alice:p%40ss@127.0.0.1:8443",
		"https://alice:p%40ss@[::1]:8443",
	} {
		p, err := NewResolver().Resolve(t.Context(), uri)
		if err != nil || p.Type != "http" || p.UDP.Host != "" {
			t.Fatalf("HTTP profile: %v", err)
		}
		if strings.HasPrefix(uri, "https://") != (p.HTTPServerName == p.TCP.Host) {
			t.Fatal("incorrect TLS identity")
		}
		if strings.Contains(uri, "alice") && (p.Username != "alice" || p.TCP.Secret != "p@ss") {
			t.Fatal("credentials decoded incorrectly")
		}
	}
	for _, uri := range []string{
		"https://proxy.example.com", "https://proxy.example.com:0", "https://proxy.example.com:65536",
		"https://alice:secret@proxy.example.com:443/path", "https://alice:secret@proxy.example.com:443?sni=other.example.com",
		"https://alice:secret@proxy.example.com:443#name", "https://alice@proxy.example.com:443",
		"https://alice%3Aadmin:secret@proxy.example.com:443", "https://alice:secret%0D%0A@proxy.example.com:443",
		"https://alice:secret@proxy.example.com:invalid",
	} {
		_, err := ParseHTTPConnect(uri)
		if err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatalf("invalid URI or unsafe error: %v", err)
		}
	}
}
