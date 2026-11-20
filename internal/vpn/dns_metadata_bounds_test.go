package vpn

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"bimeron/internal/routing"
	"golang.org/x/net/dns/dnsmessage"
)

func cnameResource(t testing.TB, owner, target string, ttl uint32) dnsmessage.Resource {
	t.Helper()
	o, err := dnsmessage.NewName(owner + ".")
	if err != nil {
		t.Fatal(err)
	}
	g, err := dnsmessage.NewName(target + ".")
	if err != nil {
		t.Fatal(err)
	}
	return dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: o, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: ttl}, Body: &dnsmessage.CNAMEResource{CNAME: g}}
}

func manyAddresses(t testing.TB, domain string, n int) []dnsmessage.Resource {
	t.Helper()
	name, err := dnsmessage.NewName(domain + ".")
	if err != nil {
		t.Fatal(err)
	}
	answers := make([]dnsmessage.Resource, 0, n)
	for i := range n {
		answers = append(answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 300}, Body: &dnsmessage.AResource{A: [4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}}})
	}
	return answers
}

// reversedChain lists a CNAME chain from the last hop back to the queried name.
func reversedChain(t testing.TB, domain string, hops int, address [4]byte) []dnsmessage.Resource {
	t.Helper()
	names := []string{domain}
	for i := range hops {
		names = append(names, fmt.Sprintf("hop%d.example.net", i))
	}
	var answers []dnsmessage.Resource
	for i := hops; i > 0; i-- {
		answers = append(answers, cnameResource(t, names[i-1], names[i], 300))
	}
	last := manyAddresses(t, names[hops], 1)[0]
	last.Body = &dnsmessage.AResource{A: address}
	return append(answers, last)
}

func checkHeap(t *testing.T, m *DNSMetadata) {
	t.Helper()
	total := 0
	for ip, domains := range m.entries {
		if len(domains) == 0 {
			t.Fatal("empty domain set retained")
		}
		for domain, e := range domains {
			if e.ip != ip || e.domain != domain || e.index < 0 || e.index >= len(m.expiry) || m.expiry[e.index] != e {
				t.Fatal("heap and map disagree")
			}
			total++
		}
	}
	if total != m.count || total != len(m.expiry) {
		t.Fatalf("count %d, map %d, heap %d", m.count, total, len(m.expiry))
	}
}

func TestDNSMetadataBoundsAddressesPerResponse(t *testing.T) {
	metadata := NewDNSMetadata()
	policy := domainPolicy(t, "example.com")
	query := metadataQuery(t, "example.com", dnsmessage.TypeA)
	metadata.Observe(query, metadataResponse(t, query, manyAddresses(t, "example.com", 1000)...), policy)
	if metadata.count != maxMetadataAddresses {
		t.Fatalf("learned %d associations, want %d", metadata.count, maxMetadataAddresses)
	}
	checkHeap(t, metadata)
	if got := metadata.Domains(netip.MustParseAddr("10.0.0.0")); len(got) != 1 {
		t.Fatal("first address was not learned", got)
	}
}

func TestDNSMetadataBoundsCNAMEChain(t *testing.T) {
	policy := domainPolicy(t, "example.com")
	query := metadataQuery(t, "example.com", dnsmessage.TypeA)

	short := NewDNSMetadata()
	short.Observe(query, metadataResponse(t, query, reversedChain(t, "example.com", maxMetadataCNAMEs, [4]byte{203, 0, 113, 70})...), policy)
	if got := short.Domains(netip.MustParseAddr("203.0.113.70")); len(got) != 1 {
		t.Fatal("reversed chain within the bound was not followed", got)
	}

	long := NewDNSMetadata()
	start := time.Now()
	long.Observe(query, metadataResponse(t, query, reversedChain(t, "example.com", 800, [4]byte{203, 0, 113, 71})...), policy)
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatal("long CNAME chain took", elapsed)
	}
	if got := long.Domains(netip.MustParseAddr("203.0.113.71")); len(got) != 0 {
		t.Fatal("chain beyond the bound was learned", got)
	}
}

func TestDNSMetadataHeapRefreshAndExpiry(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	metadata := NewDNSMetadata()
	metadata.now = func() time.Time { return clock }
	metadata.maxEntries = 3
	a, b, c, d := netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr("203.0.113.2"), netip.MustParseAddr("203.0.113.3"), netip.MustParseAddr("203.0.113.4")
	metadata.remember([]metadataAnswer{{a, "a.example", 10}, {b, "b.example", 20}, {c, "c.example", 30}})
	// Refreshing a makes b the soonest to expire.
	metadata.remember([]metadataAnswer{{a, "a.example", 100}})
	checkHeap(t, metadata)
	metadata.remember([]metadataAnswer{{d, "d.example", 40}})
	checkHeap(t, metadata)
	if len(metadata.Domains(b)) != 0 || len(metadata.Domains(a)) != 1 {
		t.Fatal("refresh did not reorder eviction")
	}
	clock = clock.Add(35 * time.Second)
	if len(metadata.Domains(c)) != 0 {
		t.Fatal("expired entry returned")
	}
	checkHeap(t, metadata)
	metadata.remember([]metadataAnswer{{b, "b.example", 5}})
	checkHeap(t, metadata)
	if metadata.count != 3 {
		t.Fatal("unexpected count", metadata.count)
	}
	clock = clock.Add(time.Hour)
	metadata.remember([]metadataAnswer{{c, "c.example", 5}})
	checkHeap(t, metadata)
	if len(metadata.Domains(a))+len(metadata.Domains(b))+len(metadata.Domains(d)) != 0 || len(metadata.Domains(c)) != 1 || metadata.count != 3 {
		t.Fatal("unexpected domains or stored count after expiry", metadata.count)
	}
}

func TestDNSMetadataEvictionTieIsInsertionOrder(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	metadata := NewDNSMetadata()
	metadata.now = func() time.Time { return clock }
	metadata.maxEntries = 2
	ip := netip.MustParseAddr("203.0.113.9")
	metadata.remember([]metadataAnswer{{ip, "z.example", 60}, {ip, "a.example", 60}, {ip, "m.example", 60}})
	got := metadata.Domains(ip)
	if len(got) != 2 || got[0] != "a.example" || got[1] != "m.example" {
		t.Fatal("oldest equal-expiry entry was not evicted first", got)
	}
}

func fullMetadata(tb testing.TB) *DNSMetadata {
	metadata := NewDNSMetadata()
	answers := make([]metadataAnswer, 0, defaultDNSMetadataEntries)
	for i := range defaultDNSMetadataEntries {
		answers = append(answers, metadataAnswer{netip.AddrFrom4([4]byte{198, 18, byte(i >> 8), byte(i)}), "filler.example", uint32(3600 + i)})
	}
	metadata.remember(answers)
	if metadata.count != defaultDNSMetadataEntries {
		tb.Fatal("table not full")
	}
	return metadata
}

func TestDNSMetadataInsertAfterBulkExpiry(t *testing.T) {
	metadata := fullMetadata(t)
	now := metadata.expiry[0].expires.Add(maxDNSMetadataTTL)
	metadata.now = func() time.Time { return now }
	oldest := metadata.expiry[0].ip
	fresh := netip.MustParseAddr("203.0.113.1")
	metadata.remember([]metadataAnswer{{fresh, "fresh.example", 60}})
	if metadata.count != defaultDNSMetadataEntries || metadata.entries[oldest] != nil {
		t.Fatal("one insert should replace only the earliest expired association")
	}
	if got := metadata.Domains(fresh); len(got) != 1 || got[0] != "fresh.example" {
		t.Fatal("missing fresh association", got)
	}
	if got := metadata.Domains(metadata.expiry[0].ip); len(got) != 0 || metadata.count != defaultDNSMetadataEntries {
		t.Fatal("lookup returned an expired association or changed the stored count", got)
	}
	checkHeap(t, metadata)
}

func TestDNSMetadataBulkExpirySameIP(t *testing.T) {
	metadata := NewDNSMetadata()
	now := time.Unix(1_700_000_000, 0)
	metadata.now = func() time.Time { return now }
	ip := netip.MustParseAddr("203.0.113.9")
	answers := []metadataAnswer{{ip, "z.example", 60}, {ip, "a.example", 60}}
	for i := len(answers); i < defaultDNSMetadataEntries; i++ {
		answers = append(answers, metadataAnswer{ip, fmt.Sprintf("expired%d.example", i), 1})
	}
	metadata.remember(answers)
	now = now.Add(time.Second)
	got := metadata.Domains(ip)
	if len(got) != 2 || got[0] != "a.example" || got[1] != "z.example" {
		t.Fatalf("unexpected live domains after bulk expiry: %v", got)
	}
	if metadata.count != len(answers) {
		t.Fatalf("lookup changed stored count to %d, want %d", metadata.count, len(answers))
	}
	checkHeap(t, metadata)
}

func TestDNSMetadataFullTableLargeAnswerIsFast(t *testing.T) {
	metadata := fullMetadata(t)
	policy := domainPolicy(t, "example.com")
	query := metadataQuery(t, "example.com", dnsmessage.TypeA)
	response := metadataResponse(t, query, manyAddresses(t, "example.com", 1000)...)
	start := time.Now()
	metadata.Observe(query, response, policy)
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatal("observe on a full table took", elapsed)
	}
	if metadata.count != defaultDNSMetadataEntries {
		t.Fatal("limit not kept", metadata.count)
	}
	checkHeap(t, metadata)
}

func BenchmarkDNSMetadataObserveFullTable(b *testing.B) {
	metadata := fullMetadata(b)
	policy, err := routing.Compile(routing.Config{Default: routing.Direct, Rules: []routing.Rule{{Domain: "example.com", Action: routing.Proxy}}})
	if err != nil {
		b.Fatal(err)
	}
	name, _ := dnsmessage.NewName("example.com.")
	query, _ := (&dnsmessage.Message{Header: dnsmessage.Header{ID: 7}, Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}).Pack()
	answers := manyAddresses(b, "example.com", 1000)
	response, _ := (&dnsmessage.Message{Header: dnsmessage.Header{ID: 7, Response: true}, Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}, Answers: answers}).Pack()
	b.ReportAllocs()
	for b.Loop() {
		metadata.Observe(query, response, policy)
	}
}
