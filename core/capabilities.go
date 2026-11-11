package core

import (
	"runtime"
	"slices"

	"bimeron/internal/config"
)

// Capabilities describes what the current build supports on this platform.
// A GUI should read these instead of assuming feature parity across targets.
type Capabilities struct {
	GeoIPSplit    bool              `json:"geoip_split"`
	GeoSiteSplit  bool              `json:"geosite_split"`
	GeoDataSchema string            `json:"geodata_schema"`
	IKEv2         IKEv2Capabilities `json:"ikev2"`
	Platform      string            `json:"platform"`
	VPN           bool              `json:"vpn"`
	Proxy         bool              `json:"proxy"`
	IPv4          bool              `json:"ipv4"`
	IPv6          bool              `json:"ipv6"`
	IPSplit       bool              `json:"ip_split"`
	DomainSplit   bool              `json:"domain_split"`
	AppSplit      bool              `json:"app_split"`
	KillSwitch    bool              `json:"kill_switch"`
	Daemon        bool              `json:"daemon"`
	// ExplicitAccess lists protocols accepted as explicit [AccessKey]
	// parameters; "naive_quic" is Type = naive with Network = quic.
	ExplicitAccess []string `json:"explicit_access"`
	// AccessConversion reports the document operations access_to_fields and
	// access_to_uri, which convert [AccessKey] between a URI and parameters.
	AccessConversion bool `json:"access_conversion"`
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
	c := Capabilities{GeoIPSplit: true, GeoSiteSplit: true, GeoDataSchema: "v2ray-protobuf", Platform: runtime.GOOS, Proxy: true, IPv4: true, IPv6: true, IPSplit: true, Daemon: true, ExplicitAccess: slices.Clone(config.ExplicitAccess), AccessConversion: true}
	if runtime.GOOS == "windows" {
		c.IKEv2 = IKEv2Capabilities{Supported: true, ForegroundOnly: true, PreconfiguredProfile: true, AdministratorRequired: true, KillSwitch: true, DNSProtection: true}
	}
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
