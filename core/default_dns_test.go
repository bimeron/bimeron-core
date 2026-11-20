package core

import (
	"encoding/json"
	"reflect"
	"testing"

	"bimeron/internal/config"
	"bimeron/internal/dnsconfig"
)

var wantDefaultDNS = []string{"1.1.1.1", "1.0.0.1"}

func TestDefaultDNSIsAPair(t *testing.T) {
	if got := DefaultConfig().DNS; !reflect.DeepEqual(got, wantDefaultDNS) {
		t.Fatal("DefaultConfig DNS", got)
	}
	if parsed, err := dnsconfig.Parse(config.DefaultDNS); err != nil || !reflect.DeepEqual(parsed, wantDefaultDNS) {
		t.Fatal("profile parser default", parsed, err)
	}
	// A profile without [Interface] DNS gets the same servers, in order.
	c, err := LoadConfigData([]byte("[Profile]\nVersion = 1\n[AccessKey]\nSS = ss://aes-256-gcm:s@example.com:8388\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(c.DNS, wantDefaultDNS) {
		t.Fatal("profile default DNS", c.DNS)
	}
	if err := c.validate(); err != nil {
		t.Fatal(err)
	}
	// Explicit values are unchanged.
	c, err = LoadConfigData([]byte("[Profile]\nVersion = 1\n[AccessKey]\nSS = ss://aes-256-gcm:s@example.com:8388\n[Interface]\nDNS = 9.9.9.9\n"))
	if err != nil || !reflect.DeepEqual(c.DNS, []string{"9.9.9.9"}) {
		t.Fatal("explicit DNS", c.DNS, err)
	}
}

func TestDefaultDNSCapability(t *testing.T) {
	b, err := json.Marshal(PlatformCapabilities())
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		DefaultDNS []string `json:"default_dns"`
	}
	if err := json.Unmarshal(b, &report); err != nil || !reflect.DeepEqual(report.DefaultDNS, wantDefaultDNS) {
		t.Fatal("default_dns", report.DefaultDNS, err)
	}
}
