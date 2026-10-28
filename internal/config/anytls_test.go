package config

import "testing"

func TestAnyTLSSource(t *testing.T) {
	for _, source := range []string{"AnyTLS", "Key"} {
		data := []byte("[Profile]\nVersion = 1\n[AccessKey]\n" + source + " = anytls://secret@example.com:443?sni=example.com\n")
		c, err := ParseData(data)
		if err != nil {
			t.Fatal(err)
		}
		p, err := c.Resolve(nil)
		if err != nil || p.Type != "anytls" {
			t.Fatalf("AnyTLS config: %#v, %v", p, err)
		}
	}
	data := []byte("[Profile]\nVersion = 1\n[AccessKey]\nAnyTLS = anytls://secret@example.com\nTrojan = trojan://secret@example.com:443\n")
	if _, err := ParseData(data); err == nil {
		t.Fatal("multiple sources accepted")
	}
}
