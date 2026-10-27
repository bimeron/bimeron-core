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
	withTLSOptions := strings.Replace(base, `"sni":"example.com"`, `"sni":"example.com","alpn":"http/1.1","fp":"chrome"`, 1)
	withOptions, err := ParseVMess(vmessLink(withTLSOptions))
	if err != nil || withOptions.VMess.ALPN != "http/1.1" || withOptions.VMess.Fingerprint != "chrome" {
		t.Fatalf("VMess TLS options: %#v, %v", withOptions.VMess, err)
	}
	upgrade := strings.Replace(base, `"net":"ws"`, `"net":"httpupgrade"`, 1)
	if p, err := ParseVMess(vmessLink(upgrade)); err != nil || p.VMess.Network != "httpupgrade" {
		t.Fatalf("VMess HTTPUpgrade: %#v, %v", p.VMess, err)
	}
	grpc := strings.Replace(strings.Replace(base, `"net":"ws"`, `"net":"grpc"`, 1), `"path":"/vpn"`, `"path":"vmess"`, 1)
	if p, err := ParseVMess(vmessLink(grpc)); err != nil || p.VMess.GRPCServiceName != "vmess" || p.VMess.GRPCAuthority != "front.example.com" {
		t.Fatalf("VMess gRPC: %#v, %v", p.VMess, err)
	}
	grpcMulti := strings.Replace(grpc, `"net":"grpc"`, `"net":"grpc","mode":"multi"`, 1)
	if p, err := ParseVMess(vmessLink(grpcMulti)); err != nil || !p.VMess.GRPCMultiMode {
		t.Fatalf("VMess gRPC multi: %#v, %v", p.VMess, err)
	}
	xhttp := strings.Replace(base, `"net":"ws"`, `"net":"xhttp"`, 1)
	if p, err := ParseVMess(vmessLink(xhttp)); err != nil || p.VMess.XHTTPPath != "/vpn" || p.VMess.XHTTPMode != "auto" {
		t.Fatalf("VMess XHTTP: %#v, %v", p.VMess, err)
	}
	xhttpStream := strings.Replace(xhttp, `"net":"xhttp"`, `"net":"xhttp","mode":"stream-up"`, 1)
	if p, err := ParseVMess(vmessLink(xhttpStream)); err != nil || p.VMess.XHTTPMode != "stream-up" {
		t.Fatalf("VMess XHTTP stream-up: %#v, %v", p.VMess, err)
	}
	xhttpOne := strings.Replace(xhttp, `"net":"xhttp"`, `"net":"xhttp","mode":"stream-one"`, 1)
	if p, err := ParseVMess(vmessLink(xhttpOne)); err != nil || p.VMess.XHTTPMode != "stream-one" {
		t.Fatalf("VMess XHTTP stream-one: %#v, %v", p.VMess, err)
	}
	xhttpH3 := strings.Replace(xhttpOne, `"sni":"example.com"`, `"sni":"example.com","alpn":"h3"`, 1)
	if p, err := ParseVMess(vmessLink(xhttpH3)); err != nil || p.VMess.ALPN != "h3" {
		t.Fatalf("VMess XHTTP HTTP/3: %#v, %v", p.VMess, err)
	}
	xhttpExtra := strings.Replace(xhttp, `"net":"xhttp"`, `"net":"xhttp","extra":"{\"headers\":{\"X-Test\":\"value\"}}"`, 1)
	if p, err := ParseVMess(vmessLink(xhttpExtra)); err != nil || p.VMess.XHTTPOptions == nil || p.VMess.XHTTPOptions.Headers["X-Test"] != "value" {
		t.Fatalf("VMess XHTTP extra: %#v, %v", p.VMess, err)
	}
	reality := strings.Replace(strings.Replace(base, `"net":"ws"`, `"net":"tcp"`, 1), `"tls":"tls"`, `"tls":"reality","fp":"chrome","pbk":"`+base64.RawURLEncoding.EncodeToString(make([]byte, 32))+`","sid":"abcd"`, 1)
	reality = strings.Replace(strings.Replace(reality, `"host":"front.example.com"`, `"host":""`, 1), `"path":"/vpn"`, `"path":""`, 1)
	if p, err := ParseVMess(vmessLink(reality)); err != nil || p.VMess.TLS != "reality" || p.VMess.ShortID != "abcd" {
		t.Fatalf("VMess REALITY: %#v, %v", p.VMess, err)
	}
	for _, bad := range []string{
		strings.Replace(base, `"aid":"0"`, `"aid":"1"`, 1),
		strings.Replace(base, `"tls":"tls"`, `"tls":""`, 1),
		strings.Replace(base, `"scy":"auto"`, `"scy":"none"`, 1),
		strings.Replace(base, `"scy":"auto"`, `"scy":"zero"`, 1),
		strings.Replace(base, `"net":"ws"`, `"net":"kcp"`, 1),
		strings.Replace(base, `"id":"123e4567-e89b-12d3-a456-426614174000"`, `"id":"private-id"`, 1),
		strings.Replace(base, `"path":"/vpn"`, `"path":"https://invalid"`, 1),
		strings.Replace(base, `"v":"2"`, `"v":"2","evil":true`, 1),
		strings.Replace(base, `"v":"2"`, `"v":"2","v":"2"`, 1),
		base + `{"extra":true}`,
		strings.Replace(base, `"scy":"auto"`, `"scy":false`, 1),
		strings.Replace(base, `"sni":"example.com"`, `"sni":"example.com","alpn":"h2"`, 1),
		strings.Replace(base, `"sni":"example.com"`, `"sni":"example.com","fp":"unknown"`, 1),
		strings.Replace(xhttp, `"net":"xhttp"`, `"net":"xhttp","mode":"bad"`, 1),
		strings.Replace(xhttp, `"net":"xhttp"`, `"net":"xhttp","extra":"{\"evil\":true}"`, 1),
		strings.Replace(xhttp, `"net":"xhttp"`, `"net":"xhttp","extra":""`, 1),
		strings.Replace(base, `"net":"ws"`, `"net":"ws","extra":""`, 1),
		strings.Replace(xhttpH3, `"alpn":"h3"`, `"alpn":"h3","fp":"chrome"`, 1),
		strings.Replace(xhttpH3, `"alpn":"h3"`, `"alpn":"h3,h2"`, 1),
		strings.Replace(grpc, `"path":"vmess"`, `"path":""`, 1),
		strings.Replace(grpc, `"path":"vmess"`, `"path":"bad/service"`, 1),
		strings.Replace(grpc, `"host":"front.example.com"`, `"host":":invalid"`, 1),
		strings.Replace(xhttp, `"sni":"example.com"`, `"sni":"example.com","alpn":"http/1.1"`, 1),
		strings.Replace(base, `"tls":"tls"`, `"tls":"reality"`, 1),
		strings.Replace(reality, `"pbk":"`+base64.RawURLEncoding.EncodeToString(make([]byte, 32))+`"`, `"pbk":"invalid"`, 1),
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
