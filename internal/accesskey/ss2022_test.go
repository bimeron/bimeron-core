package accesskey

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

func TestSS2022IdentityChains(t *testing.T) {
	for _, size := range []int{16, 32} {
		method := fmt.Sprintf("2022-blake3-aes-%d-gcm", size*8)
		key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{255}, size))
		other := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{254}, size))
		chain := key + ":" + other + ":" + key
		for i, uri := range []string{
			"ss://" + method + ":" + strings.ReplaceAll(chain, "/", "%2F") + "@example.com:8388",
			"ss://" + base64.RawURLEncoding.EncodeToString([]byte(method+":"+chain)) + "@example.com:8388",
			"ss://" + base64.StdEncoding.EncodeToString([]byte(method+":"+chain+"@example.com:8388")),
		} {
			p, err := ParseSS(uri)
			if err != nil || p.TCP.Secret != chain || p.UDP.Secret != chain {
				t.Fatalf("chain URI format %d: %v", i, err)
			}
		}
		for _, config := range []string{
			fmt.Sprintf(`{"server":"example.com","server_port":8388,"method":%q,"password":%q}`, method, chain),
			fmt.Sprintf("server: example.com\nserver_port: 8388\nmethod: %s\npassword: %s\n", method, chain),
			fmt.Sprintf("transport:\n  $type: tcpudp\n  tcp:\n    $type: shadowsocks\n    endpoint: example.com:8388\n    cipher: %s\n    secret: %s\n  udp:\n    $type: shadowsocks\n    endpoint: udp.example.com:8389\n    cipher: %s\n    secret: %s\n", method, chain, method, other+":"+key),
		} {
			p, err := ParseConfig([]byte(config))
			if err != nil || p.TCP.Secret != chain {
				t.Fatalf("chain configuration: %v", err)
			}
			if p.UDP.Host == "udp.example.com" && (p.UDP.Port != 8389 || p.UDP.Secret != other+":"+key) {
				t.Fatal("UDP configuration was overwritten")
			}
		}
		for _, invalid := range []string{"", ":" + key, key + ":", key + "::" + key, key + ":invalid", key + ":" + base64.StdEncoding.EncodeToString(make([]byte, 24)), key + "\n", key[:len(key)-1]} {
			_, err := ParseSS2022Keys(method, invalid)
			if err == nil {
				t.Fatal("invalid chain accepted")
			}
			if strings.Contains(err.Error(), key) || strings.Contains(err.Error(), "invalid:") {
				t.Fatal("credentials leaked")
			}
		}
		e := Endpoint{Host: "example.com", Port: 8388, Cipher: method, Secret: chain, Prefix: "GET "}
		if err := e.Validate(); err == nil {
			t.Fatal("identity chain accepted a salt prefix")
		}
	}
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	if _, err := ParseSS2022Keys("2022-blake3-chacha20-poly1305", key+":"+key); err == nil {
		t.Fatal("ChaCha20 chain accepted")
	}
}

func FuzzSS2022Keys(f *testing.F) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 16))
	f.Add("2022-blake3-aes-128-gcm", key)
	f.Add("2022-blake3-aes-128-gcm", key+":"+key)
	f.Add("2022-blake3-chacha20-poly1305", key+":")
	f.Fuzz(func(t *testing.T, method, secret string) {
		keys, err := ParseSS2022Keys(method, secret)
		if err != nil {
			return
		}
		parts := strings.Split(secret, ":")
		if len(keys) != len(parts) {
			t.Fatal("lost key component")
		}
		for i, key := range keys {
			if base64.StdEncoding.EncodeToString(key) != parts[i] {
				t.Fatal("noncanonical key accepted")
			}
		}
	})
}
