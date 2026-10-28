package accesskey

import (
	"context"
	"strings"
	"testing"
)

func TestParseNaive(t *testing.T) {
	p, err := ParseNaive("naive+https://alice:s%40cret@[2001:db8::1]:8443?sni=proxy.example.com&insecure=0#Home")
	if err != nil || p.Type != "naive" || p.Naive.User != "alice" || p.Naive.Password != "s@cret" || p.Naive.ServerName != "proxy.example.com" || p.TCP.Port != 8443 || p.Name != "Home" {
		t.Fatalf("unexpected NaiveProxy profile: %+v, %v", p, err)
	}
	if p, err := NewResolver().Resolve(context.Background(), "naive+https://user:pass@example.com"); err != nil || p.TCP.Port != 443 {
		t.Fatalf("resolver: %+v, %v", p, err)
	}
	for _, uri := range []string{
		"naive+https://alice:s%40cret@example.com?insecure=1",
		"naive+https://alice:s%40cret@example.com?fp=chrome",
		"naive+https://alice:s%40cret@example.com?sni=a&sni=b",
		"naive+https://alice:s%40cret@example.com/path",
		"naive+https://alice:s%40cret@example.com:0",
		"naive+https://alice@example.com",
	} {
		_, err := ParseNaive(uri)
		if err == nil || strings.Contains(err.Error(), "cret") {
			t.Fatalf("unsafe or missing error for %q: %v", uri, err)
		}
	}
}

func TestParseNaiveQUIC(t *testing.T) {
	p, err := NewResolver().Resolve(t.Context(), "naive+quic://alice:s%40cret@[::1]?sni=proxy.example.com#QUIC")
	if err != nil || !p.Naive.QUIC || !p.TCPOnly() || p.TCP.Host != "::1" || p.TCP.Port != 443 || p.Naive.Password != "s@cret" || p.Naive.ServerName != "proxy.example.com" || p.Name != "QUIC" {
		t.Fatalf("unexpected QUIC profile or error: %v", err)
	}
	for _, uri := range []string{
		"naive+quic://user:synthetic-secret@example.com?insecure=1",
		"naive+quic://user:synthetic-secret@example.com?fp=chrome",
		"naive+quic://user:synthetic-secret@example.com?alpn=h2",
		"naive+quic://user:synthetic-secret@example.com?sni=a&sni=b",
		"naive+quic://user:synthetic-secret@example.com?sni=",
		"naive+quic://user:synthetic-secret@example.com/path",
		"naive+quic://user:synthetic-secret@example.com:0",
		"naive+quic://user@example.com",
	} {
		if _, err := ParseNaive(uri); err == nil || strings.Contains(err.Error(), "synthetic-secret") {
			t.Fatalf("unsafe or missing error: %v", err)
		}
	}
	p.ShadowTLS = &ShadowTLS{ServerName: "cover.example", Password: "synthetic-secret"}
	if err := p.ValidateShadowTLS(); err == nil {
		t.Fatal("HTTP/3 accepted a TCP ShadowTLS wrapper")
	}
}
