package config

import "testing"

func TestHysteria2Source(t *testing.T) {
	for _, source := range []string{"Hysteria2", "Key"} {
		data := []byte("[Profile]\nVersion = 1\n[AccessKey]\n" + source + " = hy2://secret@example.com:443?sni=example.com\n")
		c, err := ParseData(data)
		if err != nil {
			t.Fatalf("%s: %v", source, err)
		}
		p, err := c.Resolve(t.Context())
		if err != nil || p.Type != "hysteria2" {
			t.Fatalf("%s: %+v, %v", source, p, err)
		}
	}
}

func TestHysteria2QueryAuthConfiguration(t *testing.T) {
	data := []byte("[Profile]\nVersion = 1\n[AccessKey]\nHysteria2 = hysteria2://server.example:8449?auth=fixture-pass&sni=sni.example&insecure=0&alpn=h3#Profile\n")
	c, err := ParseData(data)
	if err != nil {
		t.Fatal(err)
	}
	p, err := c.Resolve(t.Context())
	if err != nil || p.Hysteria2.Password != "fixture-pass" || p.Hysteria2.ALPN != "h3" {
		t.Fatalf("invalid query-auth profile: %v", err)
	}
}
