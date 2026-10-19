package core

import (
	"encoding/json"
	"runtime"
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
