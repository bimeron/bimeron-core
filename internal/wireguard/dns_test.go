package wireguard

import (
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func rr(name string, t dnsmessage.Type, body dnsmessage.ResourceBody) dnsmessage.Resource {
	return dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(name), Type: t, Class: dnsmessage.ClassINET}, Body: body}
}

func TestAddressesFollowCNAMEChainInAnyOrder(t *testing.T) {
	answers := []dnsmessage.Resource{
		rr("c.example.com.", dnsmessage.TypeA, &dnsmessage.AResource{A: [4]byte{192, 0, 2, 7}}),
		rr("b.example.com.", dnsmessage.TypeCNAME, &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName("c.example.com.")}),
		rr("a.example.com.", dnsmessage.TypeCNAME, &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName("b.example.com.")}),
		rr("other.example.com.", dnsmessage.TypeA, &dnsmessage.AResource{A: [4]byte{198, 51, 100, 1}}),
	}
	got := addresses(answers, dnsmessage.MustNewName("A.example.com."), dnsmessage.TypeA)
	if len(got) != 1 || got[0] != netip.MustParseAddr("192.0.2.7") {
		t.Fatalf("addresses %v", got)
	}
	loop := []dnsmessage.Resource{
		rr("a.example.com.", dnsmessage.TypeCNAME, &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName("b.example.com.")}),
		rr("b.example.com.", dnsmessage.TypeCNAME, &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName("a.example.com.")}),
	}
	if got := addresses(loop, dnsmessage.MustNewName("a.example.com."), dnsmessage.TypeA); len(got) != 0 {
		t.Fatal("CNAME loop produced addresses")
	}
	chaos := rr("a.example.com.", dnsmessage.TypeCNAME, &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName("other.example.com.")})
	chaos.Header.Class = dnsmessage.ClassCHAOS
	if got := addresses(append([]dnsmessage.Resource{chaos}, answers[3]), dnsmessage.MustNewName("a.example.com."), dnsmessage.TypeA); len(got) != 0 {
		t.Fatal("non-IN alias authorized an address")
	}
}

func TestParseHeaderAcceptsTruncatedReply(t *testing.T) {
	name := dnsmessage.MustNewName("example.com.")
	m := dnsmessage.Message{Header: dnsmessage.Header{ID: 7, Response: true, Truncated: true}, Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
		Answers: []dnsmessage.Resource{rr("example.com.", dnsmessage.TypeA, &dnsmessage.AResource{A: [4]byte{192, 0, 2, 1}})}}
	b, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	cut := b[:len(b)-3] // ends inside the answer record
	h, ok := parseHeader(cut, name, map[uint16]dnsmessage.Type{7: dnsmessage.TypeA})
	if !ok || !h.Truncated {
		t.Fatal("truncated reply not matched")
	}
	if _, ok := parseHeader(cut, name, map[uint16]dnsmessage.Type{8: dnsmessage.TypeA}); ok {
		t.Fatal("unknown ID matched")
	}
	if _, ok := parseHeader(cut, name, map[uint16]dnsmessage.Type{7: dnsmessage.TypeAAAA}); ok {
		t.Fatal("wrong type matched")
	}
}

func TestNXDOMAINStopsLookup(t *testing.T) {
	c := &Client{}
	if _, err := c.lookup(t.Context(), "bad name with spaces"); err == nil {
		t.Fatal("invalid name resolved")
	}
}
