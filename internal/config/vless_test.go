package config

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVLESSConfigSources(t *testing.T) {
	pub := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	uri := "vless://123e4567-e89b-12d3-a456-426614174000@[2604:86c0:f401:a::4]:8443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=example.com&fp=firefox&pbk=" + pub + "&sid=abcd&type=tcp"
	base := "[Profile]\nVersion = 1\n[AccessKey]\n"
	for _, source := range []string{"VLESS = " + uri, "Key = " + uri, "Type = vless\nServer = 2604:86c0:f401:a::4\nPort = 8443\nID = 123e4567-e89b-12d3-a456-426614174000\nEncryption = none\nFlow = xtls-rprx-vision\nNetwork = tcp\nSecurity = reality\nServerName = example.com\nFingerprint = firefox\nPublicKey = " + pub + "\nShortID = abcd"} {
		c, err := ParseData([]byte(base + source + "\n"))
		if err != nil {
			t.Fatal(err)
		}
		p, err := c.Resolve(t.Context())
		if err != nil || p.Type != "vless" || p.TCP.Host != "2604:86c0:f401:a::4" {
			t.Fatalf("VLESS source failed: %v", err)
		}
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "key.txt"), []byte(uri), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "test.conf"), []byte(base+"File = key.txt\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(filepath.Join(dir, "test.conf")); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseData([]byte(base + "VLESS = " + uri + "\nServer = example.com\n")); err == nil || !strings.Contains(err.Error(), "exactly one source") {
		t.Fatalf("mixed sources accepted: %v", err)
	}
}

func TestVLESSWSParameters(t *testing.T) {
	data := "[Profile]\nVersion = 1\n[AccessKey]\nType = vless\nServer = example.com\nPort = 443\nID = 123e4567-e89b-12d3-a456-426614174000\nEncryption = none\nNetwork = ws\nSecurity = tls\nServerName = example.com\nWSPath = /chat\nWSHost = front.example.com\nWSEarlyData = 2048\nALPN = http/1.1\n"
	c, err := ParseData([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	p, err := c.Resolve(t.Context())
	if err != nil || p.VLESS.WSPath != "/chat" || p.VLESS.WSHost != "front.example.com" || p.VLESS.WSEarlyData != 2048 {
		t.Fatalf("invalid WS parameters: %v", err)
	}
}

func TestVLESSHTTPParameters(t *testing.T) {
	base := "[Profile]\nVersion = 1\n[AccessKey]\nType = vless\nServer = example.com\nPort = 443\nID = 123e4567-e89b-12d3-a456-426614174000\nEncryption = none\nSecurity = tls\nServerName = example.com\n"
	for _, tc := range []struct{ fields, network string }{
		{"Network = grpc\nGRPCServiceName = proxy\nALPN = h2\n", "grpc"},
		{"Network = xhttp\nXHTTPMode = packet-up\nXHTTPPath = /stream\nXHTTPHost = front.example.com\nALPN = h2\n", "xhttp"},
	} {
		c, err := ParseData([]byte(base + tc.fields))
		if err != nil {
			t.Fatal(err)
		}
		p, err := c.Resolve(t.Context())
		if err != nil || p.VLESS.Network != tc.network {
			t.Fatalf("%s parameters: %v", tc.network, err)
		}
	}
}
