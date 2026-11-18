package killswitch

import (
	"bimeron/internal/routing"
	"fmt"
	"net/netip"
)

// EgressRule is ordered by Weight, not prefix length. It controls application
// connections outside the tunnel; core and tunnel permits have higher priority.
type EgressRule struct {
	Prefix netip.Prefix
	Allow  bool
	Weight uint64
}

// DNSPort is a transport protocol and destination port for name resolution.
// Kill switch rules block it outside the tunnel for every process but the core,
// with priority over direct CIDR permits.
type DNSPort struct {
	Protocol uint8
	Port     uint16
}

// DNSPorts lists DNS over UDP/TCP and DNS over TLS/QUIC.
var DNSPorts = []DNSPort{{6, 53}, {17, 53}, {6, 853}, {17, 853}}

func Plan(p *routing.Policy, disableIPv6 bool) ([]EgressRule, error) {
	c := p.Config()
	var rules []EgressRule
	for i, r := range c.Rules {
		if r.Domain != "" || r.GeoIP != "" || r.GeoSite != "" {
			return nil, fmt.Errorf("kill switch supports CIDR rules only")
		}
		prefix, err := netip.ParsePrefix(r.CIDR)
		if err != nil {
			return nil, fmt.Errorf("invalid kill switch CIDR")
		}
		allow := r.Action == routing.Direct
		if disableIPv6 && prefix.Addr().Is6() {
			allow = false
		}
		rules = append(rules, EgressRule{prefix.Masked(), allow, uint64(len(c.Rules)-i) + 10})
	}
	for _, cidr := range []string{"0.0.0.0/0", "::/0"} {
		p := netip.MustParsePrefix(cidr)
		allow := c.Default == routing.Direct
		if disableIPv6 && p.Addr().Is6() {
			allow = false
		}
		rules = append(rules, EgressRule{p, allow, 1})
	}
	return rules, nil
}
