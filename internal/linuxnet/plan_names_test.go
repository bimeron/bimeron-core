package linuxnet

import (
	"strings"
	"testing"

	"bimeron/internal/routing"
)

// Name resolution outside the tunnel is dropped before direct CIDR accepts:
// DNS and DNS over TLS, LLMNR and NetBIOS names; mDNS stays available.
func TestFirewallBlocksNameResolutionBeforeDirectRules(t *testing.T) {
	p, err := routing.Compile(routing.Config{Default: routing.Proxy, Rules: []routing.Rule{{CIDR: "192.168.1.0/24", Action: routing.Direct}}})
	if err != nil {
		t.Fatal(err)
	}
	script, err := Firewall("Bimeron", p, false, false)
	if err != nil {
		t.Fatal(err)
	}
	direct := strings.Index(script, "192.168.1.0/24")
	for _, rule := range []string{
		"meta l4proto { tcp, udp } th dport { 53, 853 } drop",
		"udp dport { 137, 5355 } drop",
		"tcp dport 5355 drop",
		"meta l4proto { tcp, udp } th sport 5355 drop",
	} {
		i := strings.Index(script, rule)
		if i < 0 || direct < 0 || i > direct {
			t.Fatalf("%q missing or after direct rules:\n%s", rule, script)
		}
		if tunnel := strings.Index(script, `oifname "Bimeron" accept`); tunnel < 0 || tunnel > i {
			t.Fatalf("%q precedes the tunnel accept", rule)
		}
	}
	if strings.Contains(script, "5353") {
		t.Fatal("mDNS must stay available")
	}
}
