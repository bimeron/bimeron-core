package accesskey

import (
	"strings"
	"testing"
)

func TestShadowTLSValidation(t *testing.T) {
	p := Profile{TCP: Endpoint{Host: "public.example", Port: 443, Cipher: "aes-256-gcm", Secret: "inner"}, ShadowTLS: &ShadowTLS{ServerName: "handshake.example", Password: "outer"}}
	if err := p.ValidateShadowTLS(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"", "bad name", "-bad.example", "bad..example", "bad/name", "bad\r\nHeader:value", strings.Repeat("x", 64) + ".example"} {
		q := p
		settings := *p.ShadowTLS
		q.ShadowTLS = &settings
		settings.ServerName = name
		if err := q.ValidateShadowTLS(); err == nil {
			t.Fatal("invalid handshake name accepted")
		}
	}
	for _, protocol := range []string{"socks5", "http", "hysteria2", "tuic", "unknown"} {
		q := p
		q.Type = protocol
		if err := q.ValidateShadowTLS(); err == nil {
			t.Fatalf("unsupported protocol accepted: %s", protocol)
		}
	}
	options := &XHTTPOptions{DownloadSettings: &XHTTPDownloadSettings{ALPN: "h3"}}
	if err := shadowXHTTP("h2", options); err == nil {
		t.Fatal("HTTP/3 secondary leg accepted")
	}
}
