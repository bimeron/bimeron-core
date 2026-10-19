package core

import "runtime"

// Capabilities describes what the current build supports on this platform.
// A GUI should read these instead of assuming feature parity across targets.
type Capabilities struct {
	Platform    string `json:"platform"`
	VPN         bool   `json:"vpn"`
	Proxy       bool   `json:"proxy"`
	IPv4        bool   `json:"ipv4"`
	IPv6        bool   `json:"ipv6"`
	IPSplit     bool   `json:"ip_split"`
	DomainSplit bool   `json:"domain_split"`
	AppSplit    bool   `json:"app_split"`
	KillSwitch  bool   `json:"kill_switch"`
	Daemon      bool   `json:"daemon"`
}

// PlatformCapabilities reports static build-time support. Application split is
// deferred. macOS reports no kill switch until one is implemented and validated
// on real hardware.
func PlatformCapabilities() Capabilities {
	c := Capabilities{Platform: runtime.GOOS, Proxy: true, IPv4: true, IPv6: true, IPSplit: true, Daemon: true}
	switch runtime.GOOS {
	case "windows", "linux":
		c.VPN = true
		c.DomainSplit = true
		c.KillSwitch = true
	case "darwin":
		c.VPN = true
		c.DomainSplit = true
	default:
		c.Daemon = false
		c.VPN = false
		c.IPSplit = false
	}
	return c
}
