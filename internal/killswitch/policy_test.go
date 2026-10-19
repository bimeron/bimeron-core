package killswitch

import (
	"net/netip"
	"bimeron/internal/routing"
	"testing"
)

func TestPlanPreservesFirstMatch(t *testing.T) {
	p, err := routing.Compile(routing.Config{Default: routing.Direct, Rules: []routing.Rule{
		{CIDR: "8.8.8.8/32", Action: routing.Proxy}, {CIDR: "8.8.8.0/24, 1.1.1.1/32", Action: routing.Direct},
		{CIDR: "203.0.113.0/24", Action: routing.Block},
	}})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := Plan(p, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"8.8.8.8", "8.8.8.9", "1.1.1.1", "203.0.113.1", "9.9.9.9", "2001:db8::1"} {
		ip := netip.MustParseAddr(address)
		var winner EgressRule
		for _, r := range plan {
			if r.Prefix.Contains(ip) && r.Weight > winner.Weight {
				winner = r
			}
		}
		if winner.Allow != (p.Decide(ip, "") == routing.Direct) {
			t.Fatal("policy mismatch", address)
		}
	}
}
func TestIPv6DisabledNeverPermitsInternet(t *testing.T) {
	p, _ := routing.Compile(routing.Config{Default: routing.Direct, Rules: []routing.Rule{{CIDR: "2001:db8::/32", Action: routing.Direct}}})
	plan, err := Plan(p, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range plan {
		if r.Prefix.Addr().Is6() && r.Allow {
			t.Fatal("IPv6 exception bypassed disable")
		}
	}
}
func TestDefaultProxyAndDomainRejection(t *testing.T) {
	plan, err := Plan(nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan) != 2 || plan[0].Allow || plan[1].Allow {
		t.Fatal("default permits direct")
	}
	p, _ := routing.Compile(routing.Config{Default: routing.Proxy, Rules: []routing.Rule{{Domain: "example.com", Action: routing.Direct}}})
	if _, err := Plan(p, false); err == nil {
		t.Fatal("unrepresentable rule accepted")
	}
}
