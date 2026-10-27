package config

import "testing"

func TestTUICSource(t *testing.T) {
	base := "[Profile]\nVersion = 1\n[AccessKey]\nTUIC = tuic://123e4567-e89b-12d3-a456-426614174000:secret@example.com:443?udp_relay_mode=quic\n"
	c, err := ParseData([]byte(base))
	if err != nil {
		t.Fatal(err)
	}
	p, err := c.Resolve(nil)
	if err != nil || p.Type != "tuic" {
		t.Fatalf("TUIC config: %+v, %v", p, err)
	}
	if _, err := ParseData([]byte(base + "Trojan = trojan://secret@example.com:443\n")); err == nil {
		t.Fatal("multiple access key sources accepted")
	}
}
