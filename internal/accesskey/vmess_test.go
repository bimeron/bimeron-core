package accesskey

import (
	"encoding/base64"
	"strings"
	"testing"
)

func vmessLink(json string) string {
	return "vmess://" + base64.StdEncoding.EncodeToString([]byte(json))
}

func TestParseVMess(t *testing.T) {
	base := `{"v":"2","ps":"test","add":"example.com","port":"443","id":"123e4567-e89b-12d3-a456-426614174000","aid":"0","scy":"auto","net":"ws","type":"none","host":"front.example.com","path":"/vpn","tls":"tls","sni":"example.com"}`
	p, err := ParseVMess(vmessLink(base))
	if err != nil || p.Type != "vmess" || p.VMess.Network != "ws" || p.VMess.WSHost != "front.example.com" || p.TCP.Port != 443 {
		t.Fatalf("unexpected VMess profile: %#v, %v", p, err)
	}
	urlSafe := "vmess://" + base64.RawURLEncoding.EncodeToString([]byte(strings.ReplaceAll(base, `"port":"443"`, `"port":443`)))
	if _, err := ParseVMess(urlSafe); err != nil {
		t.Fatalf("URL-safe VMess profile: %v", err)
	}
	for _, bad := range []string{
		strings.Replace(base, `"aid":"0"`, `"aid":"1"`, 1),
		strings.Replace(base, `"tls":"tls"`, `"tls":""`, 1),
		strings.Replace(base, `"scy":"auto"`, `"scy":"none"`, 1),
		strings.Replace(base, `"net":"ws"`, `"net":"grpc"`, 1),
		strings.Replace(base, `"id":"123e4567-e89b-12d3-a456-426614174000"`, `"id":"private-id"`, 1),
		strings.Replace(base, `"path":"/vpn"`, `"path":"https://invalid"`, 1),
		strings.Replace(base, `"v":"2"`, `"v":"2","evil":true`, 1),
		strings.Replace(base, `"v":"2"`, `"v":"2","v":"2"`, 1),
		base + `{"extra":true}`,
		strings.Replace(base, `"scy":"auto"`, `"scy":false`, 1),
	} {
		_, err := ParseVMess(vmessLink(bad))
		if err == nil {
			t.Fatalf("accepted invalid VMess profile: %s", bad)
		}
		if strings.Contains(err.Error(), "private-id") || strings.Contains(err.Error(), "123e4567") {
			t.Fatalf("leaked credential: %v", err)
		}
	}
}
