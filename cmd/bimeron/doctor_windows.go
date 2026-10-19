//go:build windows

package main

import (
	"context"
	"bimeron/internal/killswitch"
	"bimeron/internal/windowsnet"
	"time"
)

func hostDiagnostics(ctx context.Context) []diagnosticCheck {
	var checks []diagnosticCheck
	attempt, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	d, err := windowsnet.InspectDiagnostics(attempt)
	if err != nil {
		checks = append(checks, diagnosticCheck{Name: "system_network_inspection", Result: "unavailable_or_permission_denied"})
	} else {
		checks = append(checks, diagnosticCheck{Name: "windows_service", Result: d.Service})
		for _, check := range []struct {
			name  string
			count int
		}{{"tunnel_adapters", d.Adapters}, {"tunnel_adapters_up", d.Up}, {"captured_ipv4_routes", d.Routes4}, {"captured_ipv6_routes", d.Routes6}, {"owned_dns_rules", d.DNSRules}, {"owned_tunnel_dns_rules", d.TunnelDNSRules}} {
			count := check.count
			checks = append(checks, diagnosticCheck{Name: check.name, Result: "observed", Count: &count})
		}
	}
	if !windowsnet.Elevated() {
		return append(checks, diagnosticCheck{Name: "kill_switch_filters", Result: "requires_elevation"})
	}
	present, err := killswitch.Pending()
	result := "absent"
	if err != nil {
		result = "unavailable"
	} else if present {
		result = "present"
	}
	return append(checks, diagnosticCheck{Name: "kill_switch_filters", Result: result})
}
