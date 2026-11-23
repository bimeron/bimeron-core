package core

import (
	"runtime"
	"slices"

	"bimeron/internal/config"
	"bimeron/internal/wgconf"
)

// Capabilities describes what the current build supports on this platform.
// A GUI should read these instead of assuming feature parity across targets.
type Capabilities struct {
	ConditionalRecoveryContract int               `json:"conditional_recovery_contract,omitempty"`
	GuardedRestoreContract      int               `json:"guarded_restore_contract,omitempty"`
	GeoIPSplit                  bool              `json:"geoip_split"`
	GeoSiteSplit                bool              `json:"geosite_split"`
	GeoDataSchema               string            `json:"geodata_schema"`
	IKEv2                       IKEv2Capabilities `json:"ikev2"`
	Platform                    string            `json:"platform"`
	VPN                         bool              `json:"vpn"`
	Proxy                       bool              `json:"proxy"`
	IPv4                        bool              `json:"ipv4"`
	IPv6                        bool              `json:"ipv6"`
	IPSplit                     bool              `json:"ip_split"`
	DomainSplit                 bool              `json:"domain_split"`
	AppSplit                    bool              `json:"app_split"`
	KillSwitch                  bool              `json:"kill_switch"`
	Daemon                      bool              `json:"daemon"`
	// ExplicitAccess lists protocols accepted as explicit [AccessKey]
	// parameters; "naive_quic" is Type = naive with Network = quic.
	ExplicitAccess []string `json:"explicit_access"`
	// AccessConversion reports the document operations access_to_fields and
	// access_to_uri, which convert [AccessKey] between a URI and parameters.
	AccessConversion bool `json:"access_conversion"`
	// ReconnectNow reports the daemon command reconnect_now, which ends a
	// pending recovery wait or retries a failed session with a held kill switch.
	ReconnectNow bool `json:"reconnect_now"`
	// KillSwitchHold reports that an enabled kill switch is held from Start
	// until an explicit stop, including recovery waits and failed, and that
	// Status.KillSwitch publishes it.
	KillSwitchHold bool `json:"kill_switch_hold"`
	// KillSwitchUpdateHold reports that the service accepts prepare_update and
	// keeps kill switch protection across a client-requested service update
	// (ADR 0041). Read it from the installed service before the update.
	KillSwitchUpdateHold bool `json:"kill_switch_update_hold"`
	// KillSwitchUpdateResume reports support for claiming a verified residual.
	KillSwitchUpdateResume bool `json:"kill_switch_update_resume,omitempty"`
	// SOCKSAuth reports optional RFC 1929 username/password authentication
	// on the proxy-mode listener ([Interface] ListenUsername/ListenPassword).
	SOCKSAuth bool `json:"socks_auth"`
	// DoH reports support for explicit VPN DNS-over-HTTPS profiles.
	DoH bool `json:"doh"`
	// DefaultDNS lists, in priority order, the [Interface] DNS servers Core
	// uses when a profile omits DNS. GUIs should show it instead of a
	// hard-coded value; older cores omit it and default to 1.1.1.1 only.
	DefaultDNS []string `json:"default_dns"`
	// WireGuard describes WireGuard and AmneziaWG upstream support. Older
	// daemons omit it; treat absence as unsupported.
	WireGuard *WireGuardCapabilities `json:"wireguard,omitempty"`
}

// WireGuardCapabilities reports build support for WireGuard and AmneziaWG
// client profiles and the "bimeron wireguard" document bridge version.
type WireGuardCapabilities struct {
	Supported       bool     `json:"supported"`
	Experimental    bool     `json:"experimental"`
	Protocols       []string `json:"protocols"`
	AWGVersions     []string `json:"awg_versions"`
	URISchemes      []string `json:"uri_schemes"`
	AllowedIPsModes []string `json:"allowed_ips_modes"`
	DocumentAPI     int      `json:"document_api"`
	// KeyOperations lists the key operations of the CLI bridge; empty
	// where the bridge does not exist.
	KeyOperations []string `json:"key_operations,omitempty"`
}

// WireGuardSupport returns the static WireGuard capability object.
func WireGuardSupport() *WireGuardCapabilities {
	return &WireGuardCapabilities{Supported: true, Experimental: true, Protocols: []string{wgconf.ProtocolWireGuard, wgconf.ProtocolAmneziaWG}, AWGVersions: slices.Clone(wgconf.AWGVersions), URISchemes: []string{"vpn", "wireguard", "wg"}, AllowedIPsModes: slices.Clone(config.AllowedIPsModes), DocumentAPI: 1, KeyOperations: slices.Clone(wgconf.KeyOperations)}
}

// IKEv2Capabilities applies only to the system backend. Top-level flags retain
// their existing packet-backend meaning. Supported is build support, not a
// successful native profile/credential/permission probe.
type IKEv2Capabilities struct {
	AuthSubmission           bool `json:"auth_submission"`
	AuthAttemptOnly          bool `json:"auth_attempt_only"`
	AuthWindowsPersistence   bool `json:"auth_windows_persistence"`
	AuthCertificateSelection bool `json:"auth_certificate_selection"`
	AuthSmartCardInteraction bool `json:"auth_smart_card_interaction"`
	AdministratorRequired    bool `json:"administrator_required"`
	Supported                bool `json:"supported"`
	ForegroundOnly           bool `json:"foreground_only"`
	PreconfiguredProfile     bool `json:"preconfigured_profile"`
	Proxy                    bool `json:"proxy"`
	IPSplit                  bool `json:"ip_split"`
	DomainSplit              bool `json:"domain_split"`
	KillSwitch               bool `json:"kill_switch"`
	DNSProtection            bool `json:"dns_protection"`
	Stats                    bool `json:"stats"`
}

// PlatformCapabilities reports static build-time support. Application split is
// deferred. macOS reports no kill switch until one is implemented and validated
// on real hardware.
func PlatformCapabilities() Capabilities {
	c := Capabilities{DoH: true, GeoIPSplit: true, GeoSiteSplit: true, GeoDataSchema: "v2ray-protobuf", Platform: runtime.GOOS, Proxy: true, IPv4: true, IPv6: true, IPSplit: true, Daemon: true, ExplicitAccess: slices.Clone(config.ExplicitAccess), AccessConversion: true, ReconnectNow: true, WireGuard: WireGuardSupport(), SOCKSAuth: true, DefaultDNS: slices.Clone(DefaultConfig().DNS)}
	if runtime.GOOS == "windows" {
		c.KillSwitchUpdateHold = true
		c.IKEv2 = IKEv2Capabilities{Supported: true, ForegroundOnly: true, PreconfiguredProfile: true, AdministratorRequired: true, KillSwitch: true, DNSProtection: true}
	}
	switch runtime.GOOS {
	case "windows", "linux":
		c.VPN = true
		c.DomainSplit = true
		c.KillSwitch = true
		c.KillSwitchHold = true
	case "darwin":
		c.VPN = true
		c.DomainSplit = true
	default:
		c.Daemon = false
		c.ReconnectNow = false
		c.VPN = false
		c.IPSplit = false
	}
	return c
}
