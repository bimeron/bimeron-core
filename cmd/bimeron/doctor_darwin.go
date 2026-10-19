//go:build darwin

package main

import (
	"context"
	"bimeron/internal/macnet"
	"time"
)

func hostDiagnostics(ctx context.Context) []diagnosticCheck {
	attempt, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	diagnostics, err := macnet.NewManager().InspectDiagnostics(attempt)
	if err != nil {
		return []diagnosticCheck{{Name: "system_network_inspection", Result: "unavailable_or_permission_denied"}}
	}
	checks := []diagnosticCheck{
		{Name: "system_network_inspection", Result: "available"},
		{Name: "effective_dns", Result: diagnostics.EffectiveDNS},
		{Name: "dns_provider_conflict", Result: diagnostics.DNSConflict},
	}
	for _, check := range []struct {
		name  string
		count int
	}{
		{"active_network_services", diagnostics.ActiveServices},
		{"tunnel_dns_services", diagnostics.TunnelDNSServices},
		{"captured_ipv4_routes", diagnostics.CapturedIPv4Routes},
		{"captured_ipv6_routes", diagnostics.CapturedIPv6Routes},
	} {
		count := check.count
		checks = append(checks, diagnosticCheck{Name: check.name, Result: "observed", Count: &count})
	}
	return checks
}
