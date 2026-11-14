package core

import (
	"encoding/json"
	"runtime"
	"slices"
	"testing"
)

func TestPlatformCapabilities(t *testing.T) {
	c := PlatformCapabilities()
	if c.Platform != runtime.GOOS {
		t.Fatal(c)
	}
	if !c.Proxy || !c.IPv4 {
		t.Fatal(c)
	}
	if !c.DomainSplit || c.AppSplit {
		t.Fatal("incorrect split-routing capabilities")
	}
	switch runtime.GOOS {
	case "windows", "linux":
		if !c.VPN || !c.KillSwitch || !c.Daemon {
			t.Fatal(c)
		}
	case "darwin":
		if !c.VPN || c.KillSwitch || !c.Daemon {
			t.Fatal("macOS must not report kill switch")
		}
	default:
		if c.VPN || c.Daemon {
			t.Fatal(c)
		}
	}
	b, err := json.Marshal(c)
	if err != nil || b == nil {
		t.Fatal(err)
	}
}

func TestExplicitAccessCapability(t *testing.T) {
	b, err := json.Marshal(PlatformCapabilities())
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		ExplicitAccess   []string `json:"explicit_access"`
		AccessConversion bool     `json:"access_conversion"`
	}
	if err := json.Unmarshal(b, &report); err != nil {
		t.Fatal(err)
	}
	if !report.AccessConversion {
		t.Fatal("access_conversion is not reported")
	}
	for _, want := range []string{"shadowsocks", "vless", "trojan", "hysteria2", "tuic", "anytls", "vmess", "naive_quic"} {
		if !slices.Contains(report.ExplicitAccess, want) {
			t.Fatalf("explicit_access lacks %q: %v", want, report.ExplicitAccess)
		}
	}
}
