package dnsconfig

import (
	"net/netip"
	"strings"

	"bimeron/internal/problem"
)

// Parse accepts one to four distinct IPv4 resolvers in priority order.
func Parse(value string) ([]string, error) {
	parts := strings.Split(value, ",")
	if len(parts) > 4 {
		return nil, problem.New("dns_too_many", "DNS supports at most 4 resolvers").Arg("max", "4")
	}
	result := make([]string, 0, len(parts))
	seen := map[string]bool{}
	for _, part := range parts {
		ip, err := netip.ParseAddr(strings.TrimSpace(part))
		if err != nil || !ip.Is4() || !ip.IsGlobalUnicast() {
			return nil, problem.New("dns_invalid", "DNS must contain unicast IPv4 addresses separated by commas")
		}
		value := ip.String()
		if seen[value] {
			return nil, problem.New("dns_duplicate", "duplicate DNS resolver")
		}
		seen[value] = true
		result = append(result, value)
	}
	return result, nil
}
