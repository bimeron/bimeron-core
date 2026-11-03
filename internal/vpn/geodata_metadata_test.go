package vpn

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"bimeron/internal/routing"
	"golang.org/x/net/dns/dnsmessage"
)

func TestGeoSiteTrustedDNSMetadata(t *testing.T) {
	// GeoSiteList: TEST contains RootDomain example.org, encoded using V2Ray's schema.
	site := []byte{10, 25, 10, 4, 'T', 'E', 'S', 'T', 18, 17, 8, 2, 18, 11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'o', 'r', 'g'}
	// The message lengths include only their contained fields.
	site[1] = byte(len(site) - 2)
	site[9] = byte(len(site) - 10)
	data, err := routing.DecodeGeoData(nil, site)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := routing.CompileWithGeoData(routing.Config{Default: routing.Direct, Rules: []routing.Rule{{GeoSite: "test", Action: routing.Block}}}, data)
	if err != nil {
		t.Fatal(err)
	}
	metadata := NewDNSMetadata()
	clock := time.Unix(1700000000, 0)
	metadata.now = func() time.Time { return clock }
	ip := netip.MustParseAddr("203.0.113.10")
	if policy.DecideDomains(ip, metadata.Domains(ip)) != routing.Direct {
		t.Fatal("bare IP unexpectedly matched geosite")
	}
	query := metadataQuery(t, "www.example.org", dnsmessage.TypeA)
	answer := metadataResponse(t, query, aResource(t, "www.example.org", 30, [4]byte{203, 0, 113, 10}))
	metadata.Observe(query, answer, policy)
	if policy.DecideDomains(ip, metadata.Domains(ip)) != routing.Block {
		t.Fatal("GeoSite DomainRelevant did not retain trusted DNS metadata")
	}
	clock = clock.Add(30 * time.Second)
	if policy.DecideDomains(ip, metadata.Domains(ip)) != routing.Direct {
		t.Fatal("expired metadata changed routing")
	}
}

func TestGeoIPCannotOverrideIPv6Disable(t *testing.T) {
	// GeoIPList: zz contains ::/0.
	ipData := append([]byte{10, 26, 10, 2, 'z', 'z', 18, 20, 10, 16}, make([]byte, 16)...)
	ipData = append(ipData, 16, 0)
	data, err := routing.DecodeGeoData(ipData, nil)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := routing.CompileWithGeoData(routing.Config{Default: routing.Proxy, Rules: []routing.Rule{{GeoIP: "zz", Action: routing.Direct}}}, data)
	if err != nil {
		t.Fatal(err)
	}
	h := NewHandler(context.Background())
	defer h.Close()
	h.Policy = policy
	h.DisableIPv6 = true
	for _, target := range []string{"[2001:db8::1]:443", "[2001:db8::1]:53"} {
		_, action, err := h.target(target)
		if err != nil || action != routing.Block {
			t.Fatal(action, err)
		}
	}
	h.DisableIPv6 = false
	_, action, err := h.target("[2001:db8::1]:443")
	if err != nil || action != routing.Direct {
		t.Fatal(action, err)
	}
}
