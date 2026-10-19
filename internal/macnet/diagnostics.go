package macnet

import "context"

type Diagnostics struct {
	ActiveServices     int
	TunnelDNSServices  int
	CapturedIPv4Routes int
	CapturedIPv6Routes int
	EffectiveDNS       string
	DNSConflict        string
}

func (m *Manager) InspectDiagnostics(ctx context.Context) (Diagnostics, error) {
	var result Diagnostics
	services, err := m.services(ctx)
	if err != nil {
		return result, err
	}
	for _, service := range services {
		if service.Disabled {
			continue
		}
		result.ActiveServices++
		dns, err := m.dns(ctx, service.Name)
		if err != nil {
			return result, err
		}
		if equal(dns, []string{TunnelDNS}) {
			result.TunnelDNSServices++
		}
	}
	routes, err := m.routes(ctx)
	if err != nil {
		return result, err
	}
	owned := map[string]bool{}
	for _, prefix := range CaptureRoutes() {
		owned[prefix] = true
	}
	for _, route := range routes {
		if !owned[route.Prefix] || !validTunnel(route.Device) {
			continue
		}
		if route.Prefix == "::/1" || route.Prefix == "8000::/1" {
			result.CapturedIPv6Routes++
		} else {
			result.CapturedIPv4Routes++
		}
	}
	result.DNSConflict = "not_applicable"
	dns, err := m.command(ctx, "scutil", "--dns")
	if err != nil {
		return result, err
	}
	servers := ParseDefaultDNS(string(dns))
	result.EffectiveDNS = "unavailable"
	if result.TunnelDNSServices > 0 {
		result.DNSConflict = "unavailable"
	}
	if len(servers) > 0 {
		result.EffectiveDNS = "other"
		if result.TunnelDNSServices > 0 {
			result.DNSConflict = "detected"
		}
		if equal(servers, []string{TunnelDNS}) {
			result.EffectiveDNS = "tunnel"
			if result.TunnelDNSServices > 0 {
				result.DNSConflict = "not_detected"
			}
		}
	}
	return result, nil
}
