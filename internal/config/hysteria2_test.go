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
