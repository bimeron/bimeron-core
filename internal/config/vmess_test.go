package config

import (
	"encoding/base64"
	"testing"
)

func TestVMessConfig(t *testing.T) {
	link := "vmess://" + base64.StdEncoding.EncodeToString([]byte(`{"v":"2","add":"example.com","port":"443","id":"123e4567-e89b-12d3-a456-426614174000","aid":"0","scy":"auto","net":"tcp","tls":"tls"}`))
	for _, source := range []string{"VMess = " + link, "Key = " + link} {
		c, err := ParseData([]byte("[Profile]\nVersion = 1\n[AccessKey]\n" + source + "\n"))
		if err != nil {
			t.Fatal(err)
		}
		p, err := c.Resolve(nil)
		if err != nil || p.Type != "vmess" {
			t.Fatalf("VMess config resolution: %#v, %v", p, err)
		}
	}
}
