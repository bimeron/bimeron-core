package accesskey

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestParseVLESSRealityVision(t *testing.T) {
	key := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	uri := "vless://123e4567-e89b-12d3-a456-426614174000@[2604:86c0:f401:a::4]:8443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=example.com&fp=firefox&pbk=" + key + "&sid=abcd&type=tcp#IPv6%20test"
	p, err := ParseVLESS(uri)
	if err != nil {
		t.Fatal(err)
	}
	if p.Type != "vless" || p.TCP.Host != "2604:86c0:f401:a::4" || p.TCP.Port != 8443 || p.Name != "IPv6 test" || p.VLESS.Fingerprint != "firefox" {
		t.Fatalf("unexpected VLESS profile: type=%q host=%q port=%d name=%q fingerprint=%q", p.Type, p.TCP.Host, p.TCP.Port, p.Name, p.VLESS.Fingerprint)
	}
	if _, err := ParseVLESS(strings.Replace(uri, "xtls-rprx-vision", "xtls-rprx-vision-udp443", 1)); err != nil {
		t.Fatalf("rejected explicit UDP/443 flow: %v", err)
	}
	for _, suffix := range []string{"&type=ws", "&security=tls", "&unknown=value", "&sid=abc"} {
		_, err := ParseVLESS(strings.Replace(uri, "#IPv6%20test", suffix+"#IPv6%20test", 1))
		if err == nil {
			t.Fatalf("accepted unsupported URI option %q", suffix)
		}
		if strings.Contains(err.Error(), "123e4567") || strings.Contains(err.Error(), key) {
			t.Fatal("credentials leaked in parser error")
		}
	}
}

func TestParseVLESSTLS(t *testing.T) {
	base := "vless://123e4567-e89b-12d3-a456-426614174000@example.com:443?encryption=none&security=tls&sni=example.com"
	for _, tc := range []struct {
		query, network, path, host string
		early                      int
	}{
		{"&type=tcp", "tcp", "", "", 0},
		{"&type=ws&path=%2Fchat&host=front.example.com&fp=chrome", "ws", "/chat", "front.example.com", 0},
		{"&type=ws&path=%2Fchat%3Fed%3D2048", "ws", "/chat", "", 2048},
		{"&type=ws&path=%2Fchat&ed=1024", "ws", "/chat", "", 1024},
		{"&type=grpc&serviceName=proxy&alpn=h2", "grpc", "", "", 0},
		{"&type=xhttp&mode=packet-up&path=%2Fstream&alpn=h2", "xhttp", "", "", 0},
	} {
		p, err := ParseVLESS(base + tc.query)
		if err != nil || p.VLESS.Network != tc.network || p.VLESS.WSPath != tc.path || p.VLESS.WSHost != tc.host || p.VLESS.WSEarlyData != tc.early {
			t.Fatalf("TLS profile failed: %v", err)
		}
	}
	pub := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	if _, err := ParseVLESS("vless://123e4567-e89b-12d3-a456-426614174000@example.com:443?encryption=none&security=reality&sni=example.com&fp=chrome&pbk=" + pub + "&type=xhttp&mode=stream-one"); err != nil {
		t.Fatalf("REALITY XHTTP rejected: %v", err)
	}
	for _, query := range []string{
		"&type=ws&flow=xtls-rprx-vision", "&type=tcp&pbk=secret", "&type=tcp&path=%2Fchat", "&type=ws&alpn=h2", "&type=ws&path=%2Fbad%0Apath", "&type=ws&path=%2Fchat%3Fed%3D2048&ed=1024", "&type=grpc&serviceName=proxy&mode=auto", "&type=xhttp&mode=stream-up", "&type=ws&ed=9000",
	} {
		if _, err := ParseVLESS(base + query); err == nil {
			t.Fatalf("accepted invalid TLS profile")
		}
	}
}
