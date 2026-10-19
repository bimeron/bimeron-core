package dnsconfig

import (
	"fmt"
	"net/netip"
	"strings"
)

// Parse accepts one to four distinct IPv4 resolvers in priority order.
func Parse(value string) ([]string, error) {
	parts := strings.Split(value, ",")
	if len(parts) > 4 {
		return nil, fmt.Errorf("DNS supports at most 4 resolvers")
	}
	result := make([]string, 0, len(parts))
	seen := map[string]bool{}
	for _, part := range parts {
		ip, err := netip.ParseAddr(strings.TrimSpace(part))
		if err != nil || !ip.Is4() || !ip.IsGlobalUnicast() {
			return nil, fmt.Errorf("DNS must contain unicast IPv4 addresses separated by commas")
		}
		value := ip.String()
		if seen[value] {
			return nil, fmt.Errorf("duplicate DNS resolver")
		}
		seen[value] = true
		result = append(result, value)
	}
	return result, nil
}
