package core

import "bimeron/internal/problem"

// Problem is a located, catalog-coded validation failure; see docs/ERRORS.MD.
type Problem = problem.Error

// Problems returns the structured problems carried by err: an empty list for
// nil and an "unclassified" problem for an error the core cannot describe.
func Problems(err error) []*Problem { return problem.List(err) }

// ErrorCatalog returns the embedded catalog of human-readable texts for
// configuration, control and connection codes.
func ErrorCatalog() ([]byte, error) { return problem.JSON() }

// ValidateEmbeddedHost enforces the restrictions shared by the Android and
// Apple packet hosts: VPN mode without the core kill switch or IKEv2.
func ValidateEmbeddedHost(c SessionConfig) error {
	const message = "embedded packet VPN requires vpn mode without core kill switch or IKEv2"
	switch {
	case c.IKEv2 != nil:
		return problem.New("embedded_ikev2_unsupported", message).In("IKEv2")
	case c.Mode != "vpn":
		return problem.New("embedded_requires_vpn_mode", message).In("Interface").At("Mode")
	case c.KillSwitch:
		return problem.New("embedded_kill_switch_unsupported", message).In("Interface").At("KillSwitch")
	}
	return nil
}
