package config

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

const shadowProfile = "[Profile]\nVersion = 1\n[AccessKey]\nSS = ss://aes-256-gcm:inner-secret@public.example:443\n[ShadowTLS]\nServerName = handshake.example\nPassword = outer-secret\n"

func TestShadowTLSConfiguration(t *testing.T) {
	c, err := ParseData([]byte(shadowProfile))
	if err != nil {
		t.Fatal(err)
	}
	p, err := c.Resolve(t.Context())
	if err != nil || p.ShadowTLS == nil || p.ShadowTLS.ServerName != "handshake.example" || p.ShadowTLS.Password != "outer-secret" || p.TCP.Host != "public.example" || p.TCP.Secret != "inner-secret" || !p.TCPOnly() {
		t.Fatalf("wrapped profile not preserved: %v", err)
	}
	p.ShadowTLS.Password = "caller-mutated"
	second, err := c.Resolve(t.Context())
	if err != nil || second.ShadowTLS.Password != "outer-secret" {
		t.Fatal("resolved profile shares mutable wrapper settings")
	}
	for _, data := range []string{
		strings.Replace(shadowProfile, "Password = outer-secret", "", 1),
		strings.Replace(shadowProfile, "ServerName = handshake.example", "ServerName = bad/name", 1),
		shadowProfile + "Version = 2\n",
		shadowProfile + "Strict = false\n",
		shadowProfile + "[ShadowTLS]\nServerName = duplicate.example\nPassword = duplicate\n",
		strings.Replace(shadowProfile, "SS = ss://aes-256-gcm:inner-secret@public.example:443", "SOCKS5 = socks5://public.example:1080", 1),
		strings.Replace(shadowProfile, "aes-256-gcm", "aes-192-gcm", 1),
	} {
		if _, err := ParseData([]byte(data)); err == nil {
			t.Fatal("invalid wrapper configuration accepted")
		} else if strings.Contains(err.Error(), "secret") {
			t.Fatal("configuration error exposed credentials")
		}
	}
}

type shadowRoundTripper func(*http.Request) (*http.Response, error)

func (f shadowRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestShadowTLSDynamicRefreshValidation(t *testing.T) {
	c, err := ParseData([]byte(strings.Replace(shadowProfile, "SS = ss://aes-256-gcm:inner-secret@public.example:443", "SSConf = ssconf://config.example/access", 1)))
	if err != nil {
		t.Fatal(err)
	}
	key := "ss://aes-256-gcm:inner-secret@public.example:443"
	transport := shadowRoundTripper(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(key))}, nil
	})
	p, err := c.ResolveWithTransport(context.Background(), transport)
	if err != nil || p.ShadowTLS == nil {
		t.Fatalf("dynamic wrapper missing: %v", err)
	}
	key = "socks5://public.example:1080"
	if _, err := c.ResolveWithTransport(context.Background(), transport); err == nil {
		t.Fatal("dynamic refresh bypassed wrapper compatibility validation")
	}
}
