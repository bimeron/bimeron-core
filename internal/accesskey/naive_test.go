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
