package main

import "testing"

func TestIKEv2ProfileRejectsUnsafeArguments(t *testing.T) {
	for _, args := range [][]string{
		nil, {"other"}, {"profile"},
		{"profile", "-name", "VPN", "-server", "vpn.example.com", "-apply", "-remove"},
		{"profile", "-name", "VPN", "-server", "vpn.example.com", "-password", "never-accepted"},
		{"profile", "-name", "../VPN", "-server", "vpn.example.com"},
		{"profile", "-name", "VPN", "-server", "203.0.113.10"},
		{"profile", "-name", "VPN", "-server", "vpn.example.com", "extra"},
	} {
		if err := ikev2Command(args); err == nil {
			t.Fatalf("accepted invalid arguments: %v", args)
		}
	}
}
