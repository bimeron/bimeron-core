package vpn

import (
	"net/netip"
	"reflect"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"bimeron/internal/routing"
)

func metadataQuery(t *testing.T, domain string, kind dnsmessage.Type) []byte {
	t.Helper()
	name, err := dnsmessage.NewName(domain + ".")
	if err != nil {
		t.Fatal(err)
	}
	b, err := (&dnsmessage.Message{Header: dnsmessage.Header{ID: 42, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: name, Type: kind, Class: dnsmessage.ClassINET}}}).Pack()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func metadataResponse(t *testing.T, query []byte, answers ...dnsmessage.Resource) []byte {
	t.Helper()
	var request dnsmessage.Message
	if err := request.Unpack(query); err != nil {
		t.Fatal(err)
	}
	b, err := (&dnsmessage.Message{Header: dnsmessage.Header{ID: request.ID, Response: true, RecursionAvailable: true}, Questions: request.Questions, Answers: answers}).Pack()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func domainPolicy(t *testing.T, domains ...string) *routing.Policy {
	t.Helper()
	c := routing.Config{Default: routing.Direct}
	for _, domain := range domains {
		c.Rules = append(c.Rules, routing.Rule{Domain: domain, Action: routing.Proxy})
	}
	p, err := routing.Compile(c)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func aResource(t *testing.T, domain string, ttl uint32, ip [4]byte) dnsmessage.Resource {
	t.Helper()
	name, err := dnsmessage.NewName(domain + ".")
	if err != nil {
		t.Fatal(err)
	}
	return dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: ttl}, Body: &dnsmessage.AResource{A: ip}}
}

func TestDNSMetadataCNAMEAndTTL(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	metadata := NewDNSMetadata()
	metadata.now = func() time.Time { return clock }
	policy := domainPolicy(t, "example.com")
	query := metadataQuery(t, "www.example.com", dnsmessage.TypeA)
	alias, _ := dnsmessage.NewName("www.example.com.")
	target, _ := dnsmessage.NewName("edge.example.net.")
	answer := metadataResponse(t, query,
		dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: alias, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.CNAMEResource{CNAME: target}},
		aResource(t, "edge.example.net", 30, [4]byte{203, 0, 113, 10}),
	)
	metadata.Observe(query, answer, policy)
	ip := netip.MustParseAddr("203.0.113.10")
	if got := metadata.Domains(ip); !reflect.DeepEqual(got, []string{"www.example.com"}) {
		t.Fatal(got)
	}
	clock = clock.Add(30 * time.Second)
	if got := metadata.Domains(ip); len(got) != 0 {
		t.Fatal("expired metadata retained", got)
	}
}

func TestDNSMetadataCapsTTL(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	metadata := NewDNSMetadata()
	metadata.now = func() time.Time { return clock }
	policy := domainPolicy(t, "example.com")
	query := metadataQuery(t, "example.com", dnsmessage.TypeA)
	metadata.Observe(query, metadataResponse(t, query, aResource(t, "example.com", 7*24*60*60, [4]byte{203, 0, 113, 11})), policy)
	clock = clock.Add(24 * time.Hour)
	if got := metadata.Domains(netip.MustParseAddr("203.0.113.11")); len(got) != 0 {
		t.Fatal("TTL cap was not enforced", got)
	}
}

func TestDNSMetadataCollisionsAndEviction(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	metadata := NewDNSMetadata()
	metadata.now = func() time.Time { return clock }
	metadata.maxEntries = 2
	policy := domainPolicy(t, "one.example", "two.example", "three.example")
	ip := netip.MustParseAddr("203.0.113.20")
	for i, item := range []struct {
		domain string
		ttl    uint32
	}{{"one.example", 10}, {"two.example", 20}, {"three.example", 30}} {
		query := metadataQuery(t, item.domain, dnsmessage.TypeA)
		answer := metadataResponse(t, query, aResource(t, item.domain, item.ttl, [4]byte{203, 0, 113, 20}))
		metadata.Observe(query, answer, policy)
		if metadata.count > metadata.maxEntries {
			t.Fatalf("entry limit exceeded after answer %d", i)
		}
	}
	if got := metadata.Domains(ip); !reflect.DeepEqual(got, []string{"three.example", "two.example"}) {
		t.Fatal("wrong eviction or collision set", got)
	}
}

func TestDNSMetadataRejectsUnsupportedAnswers(t *testing.T) {
	metadata := NewDNSMetadata()
	policy := domainPolicy(t, "example.com")
	ip := netip.MustParseAddr("203.0.113.30")
	query := metadataQuery(t, "example.com", dnsmessage.TypeA)

	metadata.Observe(query, metadataResponse(t, query, aResource(t, "example.com", 0, [4]byte{203, 0, 113, 30})), policy)
	if got := metadata.Domains(ip); len(got) != 0 {
		t.Fatal("TTL zero was retained", got)
	}

	bad := metadataResponse(t, query, aResource(t, "example.com", 60, [4]byte{203, 0, 113, 30}))
	var response dnsmessage.Message
	_ = response.Unpack(bad)
	response.ID++
	bad, _ = response.Pack()
	metadata.Observe(query, bad, policy)
	if got := metadata.Domains(ip); len(got) != 0 {
		t.Fatal("mismatched response was retained", got)
	}

	var request dnsmessage.Message
	_ = request.Unpack(query)
	request.Questions = append(request.Questions, request.Questions[0])
	multiple, _ := request.Pack()
	metadata.Observe(multiple, metadataResponse(t, multiple, aResource(t, "example.com", 60, [4]byte{203, 0, 113, 30})), policy)
	if got := metadata.Domains(ip); len(got) != 0 {
		t.Fatal("multi-question response was retained", got)
	}
}

func TestDNSMetadataAAAAAndPrivacyFilter(t *testing.T) {
	metadata := NewDNSMetadata()
	policy := domainPolicy(t, "allowed.example")
	name, _ := dnsmessage.NewName("allowed.example.")
	query := metadataQuery(t, "allowed.example", dnsmessage.TypeAAAA)
	answer := metadataResponse(t, query, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AAAAResource{AAAA: [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}})
	metadata.Observe(query, answer, policy)
	if got := metadata.Domains(netip.MustParseAddr("2001:db8::1")); !reflect.DeepEqual(got, []string{"allowed.example"}) {
		t.Fatal(got)
	}

	unrelated := metadataQuery(t, "private.example", dnsmessage.TypeA)
	metadata.Observe(unrelated, metadataResponse(t, unrelated, aResource(t, "private.example", 60, [4]byte{203, 0, 113, 40})), policy)
	if got := metadata.Domains(netip.MustParseAddr("203.0.113.40")); len(got) != 0 {
		t.Fatal("irrelevant domain retained", got)
	}
}

func TestDNSMetadataConcurrentAccess(t *testing.T) {
	metadata := NewDNSMetadata()
	policy := domainPolicy(t, "example.com")
	query := metadataQuery(t, "example.com", dnsmessage.TypeA)
	answer := metadataResponse(t, query, aResource(t, "example.com", 60, [4]byte{203, 0, 113, 50}))
	ip := netip.MustParseAddr("203.0.113.50")
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(2)
		go func() { defer wg.Done(); metadata.Observe(query, answer, policy) }()
		go func() { defer wg.Done(); _ = metadata.Domains(ip) }()
	}
	wg.Wait()
	if got := metadata.Domains(ip); !reflect.DeepEqual(got, []string{"example.com"}) {
		t.Fatal(got)
	}
}

func BenchmarkDNSMetadataLookup(b *testing.B) {
	metadata := NewDNSMetadata()
	metadata.remember([]metadataAnswer{
		{netip.MustParseAddr("203.0.113.60"), "one.example", 60},
		{netip.MustParseAddr("203.0.113.60"), "two.example", 60},
	})
	policy, _ := routing.Compile(routing.Config{Default: routing.Direct, Rules: []routing.Rule{{Domain: "two.example", Action: routing.Proxy}}})
	ip := netip.MustParseAddr("203.0.113.60")
	b.ResetTimer()
	for b.Loop() {
		_ = policy.DecideDomains(ip, metadata.Domains(ip))
	}
}
