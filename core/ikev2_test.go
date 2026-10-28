package core

import (
	"context"
	"encoding/json"
	"runtime"
	"strings"
	"testing"

	"bimeron/internal/config"
	"bimeron/internal/routing"
)

func ikev2TestConfig() SessionConfig {
	return SessionConfig{Mode: "vpn", IKEv2: &IKEv2Config{WindowsProfile: "Corporate VPN", ServerName: "vpn.example.com"}}
}

func TestIKEv2DoesNotInheritPacketCapabilities(t *testing.T) {
	c := PlatformCapabilities().IKEv2
	if c.Supported != (runtime.GOOS == "windows") || c.Proxy || c.IPSplit || c.DomainSplit || c.KillSwitch || c.Stats {
		t.Fatal(c)
	}
	if c.Supported && (!c.ForegroundOnly || !c.PreconfiguredProfile || !c.AdministratorRequired) {
		t.Fatal(c)
	}
}

func TestIKEv2SessionConfigValidation(t *testing.T) {
	if err := ikev2TestConfig().validate(); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*SessionConfig){
		"proxy":        func(c *SessionConfig) { c.Mode = "proxy" },
		"resolver":     func(c *SessionConfig) { c.Resolve = testConfig().Resolve },
		"MTU":          func(c *SessionConfig) { c.MTU = 1420 },
		"DNS":          func(c *SessionConfig) { c.DNS = []string{"1.1.1.1"} },
		"kill switch":  func(c *SessionConfig) { c.KillSwitch = true },
		"IPv6 disable": func(c *SessionConfig) { c.DisableIPv6 = true },
		"name":         func(c *SessionConfig) { c.Name = "Bimeron" },
		"listen":       func(c *SessionConfig) { c.Listen = "127.0.0.1:1080" },
		"routing":      func(c *SessionConfig) { c.Policy, _ = routing.Compile(routing.Config{Default: routing.Block}) },
	} {
		t.Run(name, func(t *testing.T) {
			c := ikev2TestConfig()
			change(&c)
			if c.validate() == nil {
				t.Fatal("accepted packet option")
			}
		})
	}
	c, err := config.ParseData([]byte("[Profile]\nVersion = 1\n[IKEv2]\nWindowsProfile = Corporate VPN\nServerName = vpn.example.com\n"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := FromConfig(c)
	if err != nil || s.Resolve != nil || s.MTU != 0 || s.DNS != nil {
		t.Fatal(s, err)
	}
	c.IKEv2.ServerName = "mutated.example.com"
	if s.IKEv2.ServerName != "vpn.example.com" {
		t.Fatal("configuration not detached")
	}
}

func TestIKEv2StartCopiesConfigAndMarksStatsUnavailable(t *testing.T) {
	seen := make(chan SessionConfig, 1)
	e := testEngine(fakeBackend{openConfig: func(_ context.Context, c SessionConfig) (session, error) { seen <- c; return fakeSession{}, nil }})
	c := ikev2TestConfig()
	if err := e.Start(testDeadline(t), c); err != nil {
		t.Fatal(err)
	}
	c.IKEv2.ServerName = "mutated.example.com"
	awaitState(t, e, Connected)
	if got := <-seen; got.IKEv2.ServerName != "vpn.example.com" {
		t.Fatal("caller mutation leaked into session")
	}
	s := e.Status().Session
	if s.Backend != "ikev2" || s.IPv6 != "system" || !s.StatsUnavailable || !e.Stats().Unavailable {
		t.Fatal(s)
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "Corporate VPN") || strings.Contains(string(b), "vpn.example.com") {
		t.Fatal("native profile leaked in status")
	}
	if err := e.Stop(testDeadline(t)); err != nil {
		t.Fatal(err)
	}
	if !e.Stats().Unavailable {
		t.Fatal("unsupported stats became zero counters after stop")
	}
}

func TestPacketEngineRejectsSystemProfile(t *testing.T) {
	e, port, err := NewPacketEngine(Options{}, PacketOptions{MTU: 1420, Outbound: func(context.Context) (PacketNetwork, error) {
		t.Fatal("system profile entered packet path")
		return PacketNetwork{}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer port.Close()
	if err := e.Start(testDeadline(t), ikev2TestConfig()); err != nil {
		t.Fatal(err)
	}
	if err := e.Wait(testDeadline(t)); err == nil || err.Error() != "ikev2_requires_native_host_backend" {
		t.Fatal(err)
	}
}

func TestNativeSystemBackendSelection(t *testing.T) {
	if _, ok := newBackend(ikev2TestConfig()).(ikev2Backend); !ok {
		t.Fatal("system profile entered TUN backend")
	}
	if runtime.GOOS != "windows" {
		e := New(Options{})
		if err := e.Start(testDeadline(t), ikev2TestConfig()); err != nil {
			t.Fatal(err)
		}
		if err := e.Wait(testDeadline(t)); err == nil || err.Error() != "ikev2_platform_unsupported" {
			t.Fatal(err)
		}
	}
}
