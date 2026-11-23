package windowsnet

import (
	"context"
	"fmt"
	"testing"
)

// Shadow only the two read-only cmdlets, exercising the shipped script and parser.
func TestRestoreNetworkObservation(t *testing.T) {
	for _, tc := range []struct {
		name, dns, routes string
		pending, wantErr  bool
	}{
		{"owned DNS vetoes routes", "[pscustomobject]@{Comment='BimeronCore:test'}", "throw 'unexpected route read'", true, false},
		{"owned IKEv2 DNS vetoes routes", "[pscustomobject]@{Comment='BimeronIKEv2DNS:0123456789abcdef0123456789abcdef'}", "throw 'unexpected route read'", true, false},
		{"unowned DNS and unrelated route", "[pscustomobject]@{Comment='BimeronIKEv2DNS:short'}", "[pscustomobject]@{DestinationPrefix='0.0.0.0/0'}", false, false},
		{"DNS error", "throw 'DNS read failed'", "", false, true},
		{"route error", "", "throw 'route read failed'", false, true},
		{"unexpected output", "", "[Console]::Out.Write('bad')", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			script := fmt.Sprintf("function Get-DnsClientNrptRule { %s }\nfunction Get-NetRoute { param($PolicyStore) if ($PolicyStore -cne 'ActiveStore') { throw 'wrong store' }; %s }\n", tc.dns, tc.routes)
			pending, err := readRecoveryPolicy(context.Background(), script+observeRecoveryDNS+observeRecoveryRoutes)
			if pending != tc.pending || (err != nil) != tc.wantErr {
				t.Fatalf("pending=%t err=%v", pending, err)
			}
		})
	}
	for _, prefix := range []string{"0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"} {
		t.Run(prefix, func(t *testing.T) {
			script := fmt.Sprintf("function Get-DnsClientNrptRule {}\nfunction Get-NetRoute { param($PolicyStore) if ($PolicyStore -cne 'ActiveStore') { throw 'wrong store' }; [pscustomobject]@{DestinationPrefix='%s'} }\n", prefix)
			if p, err := readRecoveryPolicy(context.Background(), script+observeRecoveryDNS+observeRecoveryRoutes); err != nil || !p {
				t.Fatalf("pending=%t err=%v", p, err)
			}
		})
	}
}
