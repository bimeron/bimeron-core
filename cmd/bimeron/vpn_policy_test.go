package main

import (
	"bimeron/internal/routing"
	"net/netip"
	"os"
	"path/filepath"
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

func TestPolicyFileReadIsBounded(t *testing.T) {
	dir := t.TempDir()
	large := filepath.Join(dir, "large.json")
	// Valid JSON padded with whitespace just over the limit.
	data := append([]byte(`{"default":"proxy"}`), make([]byte, maxPolicyFile)...)
	for i := len(`{"default":"proxy"}`); i < len(data); i++ {
		data[i] = ' '
	}
	if err := os.WriteFile(large, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := vpnPolicy(large); err == nil || err.Error() != "VPN policy file exceeds the 1 MiB size limit" {
		t.Fatalf("oversized policy: %v", err)
	}
	var c routing.Config
	if err := readPolicy(dir, "policy", &c); err == nil || err.Error() != "could not read policy" {
		t.Fatalf("directory policy: %v", err)
	}
	limit := filepath.Join(dir, "limit.json")
	if err := os.WriteFile(limit, data[:maxPolicyFile], 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := vpnPolicy(limit); err != nil {
		t.Fatalf("policy at the limit: %v", err)
	}
}
