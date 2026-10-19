package routing

import (
	"net/netip"
	"testing"
)

func TestPolicy(t *testing.T) {
	p, err := Compile(Config{Default: Direct, Rules: []Rule{{CIDR: "192.168.0.0/16", Action: Direct}, {Domain: "example.com", Action: Proxy}, {CIDR: "203.0.113.0/24", Action: Block}}})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		ip, domain string
		want       Action
	}{
		{"192.168.1.1", "example.com", Direct},
		{"1.1.1.1", "WWW.Example.COM.", Proxy},
		{"1.1.1.1", "badexample.com", Direct},
		{"203.0.113.1", "", Block},
		{"::ffff:203.0.113.1", "", Block},
		{"2001:db8::1", "", Direct},
	}
	for _, c := range cases {
		if got := p.Decide(netip.MustParseAddr(c.ip), c.domain); got != c.want {
			t.Fatalf("%s %s: got %s, want %s", c.ip, c.domain, got, c.want)
		}
	}
	v6, err := Compile(Config{Default: Proxy, Rules: []Rule{{CIDR: "2001:db8::/32", Action: Direct}}})
	if err != nil {
		t.Fatal(err)
	}
	if v6.Decide(netip.MustParseAddr("2001:db8::1"), "") != Direct {
		t.Fatal("IPv6 rule ignored")
	}
}
func TestInvalidPolicies(t *testing.T) {
	for _, c := range []Config{{}, {Default: Direct, Rules: []Rule{{Action: Proxy}}}, {Default: Direct, Rules: []Rule{{CIDR: "bad", Action: Proxy}}}, {Default: Direct, Rules: []Rule{{Domain: "example.com", CIDR: "0.0.0.0/0", Action: Proxy}}}} {
		if _, err := Compile(c); err == nil {
			t.Fatal("accepted invalid policy")
		}
	}
}

func TestDomainSetUsesRuleOrder(t *testing.T) {
	ip := netip.MustParseAddr("203.0.113.10")
	p, err := Compile(Config{Default: Direct, Rules: []Rule{
		{Domain: "proxy.example", Action: Proxy},
		{CIDR: "203.0.113.0/24", Action: Block},
		{Domain: "direct.example", Action: Direct},
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, domains := range [][]string{{"direct.example", "proxy.example"}, {"proxy.example", "direct.example"}} {
		if got := p.DecideDomains(ip, domains); got != Proxy {
			t.Fatalf("DNS answer order changed decision: %v -> %s", domains, got)
		}
	}
	if !p.DomainRelevant("www.proxy.example.") || p.DomainRelevant("unrelated.example") {
		t.Fatal("domain relevance does not match policy")
	}
}

func TestDirectPrefixesPreserveEarlierRules(t *testing.T) {
	p, err := Compile(Config{Default: Proxy, Rules: []Rule{
		{CIDR: "192.168.1.0/24", Action: Direct},
		{CIDR: "203.0.113.1/32", Action: Proxy},
		{CIDR: "203.0.113.0/24", Action: Direct},
	}})
	if err != nil {
		t.Fatal(err)
	}
	prefixes := p.DirectPrefixes()
	if len(prefixes) != 1 || prefixes[0].String() != "192.168.1.0/24" {
		t.Fatal("unsafe direct prefix bypassed earlier rule", prefixes)
	}
}
