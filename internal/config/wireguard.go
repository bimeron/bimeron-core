package config

import (
	"slices"

	"bimeron/internal/accesskey"
	"bimeron/internal/problem"
	"bimeron/internal/wgconf"
)

// AllowedIPsModes lists [Routing] AllowedIPsMode values; the first is the
// default.
var AllowedIPsModes = []string{"direct", "block", "ignore", "only"}

// WireGuardOptions holds explicit Type = wireguard options in profile order.
type WireGuardOptions struct {
	keys, values []string
}

func (a *Access) addWireGuard(key, value string) {
	if a.WireGuard == nil {
		a.WireGuard = &WireGuardOptions{}
	}
	a.WireGuard.keys = append(a.WireGuard.keys, key)
	a.WireGuard.values = append(a.WireGuard.values, value)
}

// explicitWireGuard builds a profile from Type = wireguard options. Problems
// are located on the [AccessKey] option, not in a separate document.
func (c *File) explicitWireGuard() (*File, error) {
	const message = "[AccessKey] invalid WireGuard parameters"
	if c.Access.Parameters != nil || c.Access.Username != "" || c.Access.ServerName != "" {
		return nil, c.unsupported("WireGuard", message, "Server", "Port", "Method", "Password", "Prefix", "Username", "ServerName")
	}
	// Check option presence, not parsed values: zero values such as
	// WSEarlyData = 0 must be refused too. PublicKey is shared.
	others := slices.DeleteFunc(slices.Clone(vlessFields), func(f string) bool { return f == "PublicKey" })
	if c.present(others...) != "" {
		return nil, c.unsupported("WireGuard", message, others...)
	}
	fields := map[string]string{}
	if o := c.Access.WireGuard; o != nil {
		for i, key := range o.keys {
			section := wgconf.Interface
			if wgconf.PeerOption(key) {
				section = wgconf.Peer
			}
			fields[section+"/"+key] = o.values[i]
		}
	}
	text, err := wgconf.Build(fields)
	if err == nil {
		var cfg *wgconf.Config
		if cfg, err = wgconf.Parse(text); err == nil {
			p := accesskey.WireGuardProfile(c.Name, cfg)
			c.profile = &p
			return c, nil
		}
	}
	p := problem.Of(err)
	p.Document, p.Line = "", 0
	p.In("AccessKey")
	return nil, p
}

// wireGuardFile parses wg-quick text read through [AccessKey] File. Problems
// keep their location inside that text and name File as the source.
func (c *File) wireGuardFile(text string) (bool, error) {
	format, err := wgconf.Detect(text)
	if err != nil {
		p := problem.Of(err)
		if p.Code == "document_format_unknown" {
			// Not WireGuard text: read it as a URI key.
			return false, nil
		}
		// Ambiguous or non-UTF-8 text must not fall back to URI parsing.
		if p.Code == "document_format_ambiguous" {
			// A whole-text problem of the referenced file.
			p.Document = wgconf.DocumentName
			return true, p.From("File")
		}
		p.Document = ""
		return true, p.In("AccessKey").At("File").From("File")
	}
	if format != wgconf.FormatWireGuard {
		return false, nil
	}
	cfg, err := wgconf.Parse(text)
	if err != nil {
		p := problem.Of(err)
		p.Document = wgconf.DocumentName
		return true, p.From("File")
	}
	p := accesskey.WireGuardProfile(c.Name, cfg)
	c.profile = &p
	return true, nil
}

// validateAllowedIPsMode runs after the access key is known.
func (c *File) validateAllowedIPsMode() error {
	if c.AllowedIPsMode == "" {
		return nil
	}
	if !slices.Contains(AllowedIPsModes, c.AllowedIPsMode) {
		return problem.New("choice_invalid", "[Routing] AllowedIPsMode must be direct, block, ignore or only").In("Routing").At("AllowedIPsMode").Arg("allowed", "direct, block, ignore, only")
	}
	if c.profile == nil || c.profile.Type != "wireguard" {
		return problem.New("allowed_ips_mode_requires_wireguard", "[Routing] AllowedIPsMode requires a WireGuard profile").In("Routing").At("AllowedIPsMode").Arg("type", "WireGuard")
	}
	return nil
}

// IsWireGuard reports a WireGuard or AmneziaWG access key.
func (c *File) IsWireGuard() bool { return c.profile != nil && c.profile.Type == "wireguard" }

// WireGuardDNS returns the WireGuard text's IPv4 resolvers (at most four)
// when the profile does not set [Interface] DNS itself.
func (c *File) WireGuardDNS() []string {
	if !c.IsWireGuard() || c.lines["Interface.DNS"] > 0 {
		return nil
	}
	var out []string
	for _, a := range c.profile.WireGuard.DNS {
		// The same rule as [Interface] DNS: unicast IPv4 resolvers only.
		if a.Is4() && a.IsGlobalUnicast() && len(out) < 4 && !slices.Contains(out, a.String()) {
			out = append(out, a.String())
		}
	}
	return out
}

// WireGuardTunnelMTU returns the adapter MTU taken from the WireGuard text's
// MTU when the profile does not set [Interface] MTU itself, clamped to the
// adapter range 1280-1500. Zero means the profile's own or default MTU.
func (c *File) WireGuardTunnelMTU() int {
	if !c.IsWireGuard() || c.lines["Interface.MTU"] > 0 || c.profile.WireGuard.MTU == 0 {
		return 0
	}
	return min(max(c.profile.WireGuard.MTU, 1280), 1500)
}
