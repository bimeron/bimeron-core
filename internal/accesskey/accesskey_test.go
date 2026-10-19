package accesskey

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestStaticFormats(t *testing.T) {
	auth := base64.RawURLEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:p:a:ss"))
	legacy := base64.StdEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:p:a:ss@example.com:8388"))
	for _, key := range []string{"ss://" + auth + "@example.com:8388/?outline=1#demo", "ss://chacha20-ietf-poly1305:p%3Aa%3Ass@example.com:8388", "ss://" + legacy} {
		p, err := ParseSS(key)
		if err != nil {
			t.Fatal(err)
		}
		if p.TCP.Secret != "p:a:ss" || p.TCP.Host != "example.com" || p.TCP.Port != 8388 {
			t.Fatal("incorrect credentials")
		}
	}
	p, err := ParseSS("ss://aes-256-gcm:secret@[2001:db8::1]:8388")
	if err != nil || p.TCP.Host != "2001:db8::1" {
		t.Fatalf("IPv6: %v", err)
	}
}
func TestRejectedKeys(t *testing.T) {
	for _, key := range []string{"ss://bad", "ss://aes-256-gcm:s@host:0", "ss://aes-256-gcm:s@host:65536", "ss://rc4-md5:s@host:80", "ss://aes-256-gcm:s@host:80/?plugin=unsupported", "ss://aes-256-gcm:@host:80"} {
		if _, err := ParseSS(key); err == nil {
			t.Fatal("accepted invalid key")
		}
	}
}
func TestConfigFormats(t *testing.T) {
	configs := []string{
		`{"server":"example.com","server_port":8388,"method":"aes-256-gcm","password":"secret"}`,
		"server: example.com\nserver_port: 8388\nmethod: aes-256-gcm\npassword: secret\n",
		"transport:\n  $type: tcpudp\n  tcp: &shared\n    $type: shadowsocks\n    endpoint: example.com:8388\n    cipher: aes-256-gcm\n    secret: secret\n  udp:\n    <<: *shared\n",
	}
	for _, c := range configs {
		p, err := ParseConfig([]byte(c))
		if err != nil {
			t.Fatal(err)
		}
		if p.TCP.Secret != "secret" || p.UDP.Port != 8388 {
			t.Fatal("incorrect config")
		}
	}
	for _, c := range []string{"transport:\n  $type: unsupported", configs[1] + "plugin: unsupported\n", configs[1] + "---\n{}", strings.Repeat("x", maxBytes+1)} {
		if _, err := ParseConfig([]byte(c)); err == nil {
			t.Fatal("accepted invalid config")
		}
	}
}
func TestDynamicHTTPS(t *testing.T) {
	body := `{"server":"example.com","server_port":8388,"method":"aes-256-gcm","password":"secret"}`
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/bad":
			w.WriteHeader(503)
		case "/status":
			code, _ := strconv.Atoi(r.URL.Query().Get("code"))
			w.WriteHeader(code)
		case "/large":
			_, _ = w.Write([]byte(strings.Repeat("x", maxBytes+1)))
		case "/redirect":
			http.Redirect(w, r, "http://example.com", 302)
		default:
			_, _ = w.Write([]byte(body))
		}
	}))
	defer server.Close()
	resolver := NewResolver()
	resolver.client.Transport = server.Client().Transport
	key := "ssconf://" + strings.TrimPrefix(server.URL, "https://")
	p, err := resolver.Resolve(context.Background(), key+"/#demo")
	if err != nil || p.Name != "demo" {
		t.Fatalf("resolve: %v", err)
	}
	for _, path := range []string{"/bad", "/large", "/redirect"} {
		if _, err := resolver.Resolve(context.Background(), key+path); err == nil {
			t.Fatal("accepted invalid response")
		}
	}
	for _, code := range []int{401, 402, 403, 404, 410, 408, 429, 503} {
		_, err := resolver.Resolve(context.Background(), key+"/status?code="+strconv.Itoa(code))
		unavailable := code == 401 || code == 402 || code == 403 || code == 404 || code == 410
		if err == nil || IsUnavailable(err) != unavailable {
			t.Fatalf("HTTP %d: error %v, unavailable %v", code, err, IsUnavailable(err))
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := resolver.Resolve(ctx, key); err == nil {
		t.Fatal("ignored cancellation")
	}
}
