package accesskey

import (
	"context"
	"strings"
	"testing"
)

func TestAnyTLSURI(t *testing.T) {
	p, err := ParseAnyTLS("anytls://p%40ss@[::1]/?sni=localhost&insecure=0#My%20node")
	if err != nil {
		t.Fatal(err)
	}
	if p.Type != "anytls" || p.TCP.Port != 443 || p.UDP != p.TCP || p.AnyTLS.Password != "p@ss" || p.AnyTLS.ServerName != "localhost" || p.Name != "My node" {
		t.Fatalf("unexpected AnyTLS profile: %#v", p)
	}
	for _, uri := range []string{
		"anytls://secret@example.com:0",
		"anytls://secret@example.com:65536",
		"anytls://secret@example.com:443?insecure=1",
		"anytls://secret@example.com:443?insecure=0&insecure=0",
		"anytls://secret@example.com:443?sni=",
		"anytls://secret@example.com:443?fp=chrome",
		"anytls://secret@example.com:443/path",
		"anytls://user:secret@example.com:443",
	} {
		if _, err := ParseAnyTLS(uri); err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatalf("invalid URI accepted or leaked: %q: %v", uri, err)
		}
	}
	if _, err := NewResolver().Resolve(context.Background(), "anytls://secret@example.com:443"); err != nil {
		t.Fatal(err)
	}
}
