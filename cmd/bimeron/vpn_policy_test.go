package main

import (
	"net/netip"
	"os"
	"path/filepath"
	"bimeron/internal/routing"
	"testing"
)

func TestVPNAcceptsDomainPolicy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, []byte(`{"default":"proxy","rules":[{"domain":"example.com","action":"direct"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	p, err := vpnPolicy(path)
	if err != nil || p.Decide(netip.MustParseAddr("203.0.113.1"), "www.example.com") != routing.Direct {
		t.Fatal("domain policy unavailable", err)
	}
}
func TestVPNDefaultPolicy(t *testing.T) {
	if _, err := vpnPolicy(""); err != nil {
		t.Fatal(err)
	}
}
