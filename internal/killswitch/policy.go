package killswitch

import (
	"fmt"
	"net/netip"
	"bimeron/internal/routing"
)

// EgressRule is ordered by Weight, not prefix length. It controls application
// connections outside the tunnel; core and tunnel permits have higher priority.
type EgressRule struct {
	Prefix netip.Prefix
	Allow  bool
	Weight uint64
}

func Plan(p *routing.Policy, disableIPv6 bool) ([]EgressRule, error) {
	c := p.Config()
	var rules []EgressRule
	for i, r := range c.Rules {
		if r.Domain != "" {
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
