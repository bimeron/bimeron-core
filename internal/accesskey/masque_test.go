package accesskey

import (
	"context"
	"net/url"
	"strings"
	"testing"
)

func TestMASQUEProfile(t *testing.T) {
	for _, uri := range []string{"masque://proxy.example", "masque://user:secret@proxy.example:8443?sni=tls.example", "masque://[::1]:443?udp_path=" + url.QueryEscape("/proxy/{target_host}/{target_port}/")} {
		p, err := ParseMASQUE(uri)
		if err != nil || p.Type != "masque" || p.TCP.Host != p.UDP.Host || p.MASQUE.ServerName == "" {
			t.Fatalf("profile: %v", err)
		}
		resolved, err := NewResolver().Resolve(context.Background(), uri)
		if err != nil || resolved.Type != "masque" {
			t.Fatalf("resolver: %v", err)
		}
	}
	for _, uri := range []string{
		"https://proxy.example", "masque://", "masque://proxy.example:0", "masque://proxy.example:65536", "masque://proxy.example/path",
		"masque://user@proxy.example", "masque://:secret@proxy.example", "masque://:@proxy.example", "masque://user%3Aextra:secret@proxy.example",
		"masque://proxy.example?insecure=1", "masque://proxy.example?sni=a&sni=b", "masque://proxy.example?sni=", "masque://proxy.example?ca=relative.pem",
		"masque://proxy.example?udp_path=" + url.QueryEscape("//evil/{target_host}/{target_port}/"),
		"masque://proxy.example?udp_path=" + url.QueryEscape("/x/{+target_host}/{target_port}/"),
		"masque://proxy.example?udp_path=" + url.QueryEscape("/x/{target_host}/{target_port}/{unknown}"),
		"masque://proxy.example?udp_path=" + url.QueryEscape("/x/{target_host}/{target_port}/?q=x"),
	} {
		if _, err := ParseMASQUE(uri); err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatalf("invalid URI accepted or credential leaked: %v", err)
		}
	}
}
func FuzzMASQUEURI(f *testing.F) {
	for _, seed := range []string{"masque://example.com", "masque://user:secret@[::1]:443?sni=localhost", "masque://example.com?udp_path=%2Fx%2F%7Btarget_host%7D%2F%7Btarget_port%7D%2F"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, uri string) {
		p, err := ParseMASQUE(uri)
		if err == nil {
			if p.Type != "masque" || p.TCP != p.UDP {
				t.Fatal("inconsistent profile")
			}
			if err := p.MASQUE.Validate(p.TCP.Host, p.TCP.Port, p.Username, p.TCP.Secret); err != nil {
				t.Fatal(err)
			}
		}
	})
}
