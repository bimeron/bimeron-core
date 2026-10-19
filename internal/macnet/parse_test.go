package macnet

import (
	"strings"
	"testing"
)

func TestParseDefaultDNS(t *testing.T) {
	for _, test := range []struct {
		name, input string
		want        []string
	}{
		{"tunnel", "DNS configuration\n\nresolver #1\n  nameserver[0] : 198.18.0.2\n\nresolver #2\n  domain : local\n  nameserver[0] : 224.0.0.251\n", []string{"198.18.0.2"}},
		{"warp", "DNS configuration\n\nresolver #1\n  nameserver[0] : 127.0.2.2\n  nameserver[1] : 127.0.2.3\n", []string{"127.0.2.2", "127.0.2.3"}},
		{"supplemental first", "DNS configuration\n\nresolver #1\n  domain : example.test\n  nameserver[0] : 192.0.2.1\n\nresolver #2\n  nameserver[0] : 9.9.9.9\n", []string{"9.9.9.9"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := ParseDefaultDNS(test.input); !equal(got, test.want) {
				t.Fatalf("got %v, want %v", got, test.want)
			}
		})
	}
}

func TestParseRoutingTable(t *testing.T) {
	rows, err := ParseRoutes("Internet:\nDestination Gateway Flags Netif Expire\n0/1 link#12 UCS utun3\n128.0/1 link#12 UCS utun3\n198.18.0.2 link#12 UH utun3\n")
	if err != nil || len(rows) != 3 || rows[1].Prefix != "128.0.0.0/1" || rows[2].Prefix != "198.18.0.2/32" {
		t.Fatal(rows, err)
	}
	if _, err := ParseRoutes("unexpected output"); err == nil {
		t.Fatal("accepted unknown output")
	}
}
func TestBootstrapDNSUsesPhysicalInterface(t *testing.T) {
	text := "resolver #1\n nameserver[0] : 198.18.0.2\nresolver #2\n nameserver[0] : 8.8.8.8\n if_index : 4 (en0)\nresolver #3\n nameserver[0] : 9.9.9.9\n if_index : 5 (en1)\n"
	dns := ParseBootstrapDNS(text, "en0")
	if len(dns) != 1 || dns[0] != "8.8.8.8" {
		t.Fatal(dns)
	}
}
func TestDefaultRouteAndDNSValidation(t *testing.T) {
	if dev, _, err := ParseDefaultRoute("interface: en0\ngateway: 192.0.2.1"); err != nil || dev != "en0" {
		t.Fatal(dev, err)
	}
	if _, _, err := ParseDefaultRoute("interface: utun2\ngateway: 198.18.0.1"); err == nil {
		t.Fatal("accepted another tunnel as physical route")
	}
	if _, err := ParseExplicitDNS("Error: invalid service"); err == nil {
		t.Fatal("accepted command error")
	}
	if dns, err := ParseExplicitDNS("There aren't any DNS Servers set on Wi-Fi."); err != nil || len(dns) != 0 {
		t.Fatal(dns, err)
	}
	if validServiceID(strings.Repeat("x", 36)) {
		t.Fatal("accepted script injection ID")
	}
}
