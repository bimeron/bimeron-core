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
