//go:build windows

package main

import (
	"bimeron/internal/accesskey"
	"bimeron/internal/sshtunnel"
	"bimeron/internal/testutil"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/synctest"
)

// The hint is added only to a failure of a process outside the exemption
// while protection is installed, and keeps the original error.
func TestKillSwitchHint(t *testing.T) {
	failure := fmt.Errorf("check: %w", &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("blocked")})
	yes, no := func() bool { return true }, func() bool { return false }
	if err := withKillSwitchHint(nil, no, yes); err != nil {
		t.Fatal("hint without failure", err)
	}
	if err := withKillSwitchHint(failure, yes, yes); err != failure {
		t.Fatal("hint for an exempt process", err)
	}
	if err := withKillSwitchHint(failure, no, no); err != failure {
		t.Fatal("hint without protection", err)
	}
	err := withKillSwitchHint(failure, no, yes)
	if !errors.Is(err, failure) || !strings.Contains(err.Error(), "elevated administrator terminal") {
		t.Fatal("hint missing", err)
	}
	for _, local := range []error{flag.ErrHelp, errors.New("invalid policy JSON"), errors.New("proxy_listener_failed"), &net.OpError{Op: "listen", Net: "tcp", Err: errors.New("address in use")}} {
		unexpected := func() bool { t.Fatal("queried protection for", local); return false }
		if got := withKillSwitchHint(local, unexpected, unexpected); got != local {
			t.Fatal(got)
		}
	}
	if !upstreamFailure(errors.New("ssh_network_failed")) {
		t.Fatal("proxy network failure missed")
	}
}

func TestSSHNetworkHintPreservesCause(t *testing.T) {
	for _, err := range []error{sshtunnel.ErrNetwork, fmt.Errorf("SSH check: %w", sshtunnel.ErrNetwork)} {
		got := withKillSwitchHint(err, func() bool { return false }, func() bool { return true })
		if !errors.Is(got, sshtunnel.ErrNetwork) || !strings.Contains(got.Error(), "hint:") {
			t.Fatalf("missing SSH network hint: %v", got)
		}
	}
}

func TestCheckSSConfNetworkHint(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, key, message string
		network            bool
	}{
		{"refused", "ssconf://" + address + "/private-key?token=secret", "could not fetch dynamic config", true},
		{"malformed", "ssconf://%zz/private-key", "invalid ssconf URL", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "key")
			if err := os.WriteFile(path, []byte(tc.key), 0600); err != nil {
				t.Fatal(err)
			}
			err := check([]string{path})
			var raw *url.Error
			if err == nil || err.Error() != tc.message || errors.As(err, &raw) || errors.Is(err, accesskey.ErrSSConfNetwork) != tc.network {
				t.Fatalf("unexpected check error: %v", err)
			}
			hinted := withKillSwitchHint(err, func() bool { return false }, func() bool { return true })
			if strings.Contains(hinted.Error(), "hint:") != tc.network {
				t.Fatalf("unexpected hint: %v", hinted)
			}
		})
	}
}

func TestCheckSSConfNetworkFailures(t *testing.T) {
	for _, tc := range []struct {
		name, message string
		afterHeaders  bool
	}{
		{"header timeout", "could not fetch dynamic config", false},
		{"body read", "could not read config", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const key = "ssconf://private.example/private-key?token=secret"
			resolver := accesskey.NewResolverWithTransport(testutil.SSConfFailureTransport{AfterHeaders: tc.afterHeaders})
			path := filepath.Join(t.TempDir(), "key")
			if err := os.WriteFile(path, []byte(key), 0600); err != nil {
				t.Fatal(err)
			}
			synctest.Test(t, func(t *testing.T) {
				err := checkWithResolver(t.Context(), []string{path}, resolver)
				var raw *url.Error
				if err == nil || err.Error() != tc.message || errors.As(err, &raw) || !errors.Is(err, accesskey.ErrSSConfNetwork) {
					t.Fatalf("unexpected check error: %v", err)
				}
				hinted := withKillSwitchHint(err, func() bool { return false }, func() bool { return true })
				if !strings.Contains(hinted.Error(), "hint:") {
					t.Fatalf("missing hint: %v", hinted)
				}
			})
		})
	}
}

// Failed name lookups get the DNS hint whenever protection is installed, also
// for an exempt process: the system DNS client is never exempt.
func TestKillSwitchDNSHint(t *testing.T) {
	yes, no := func() bool { return true }, func() bool { return false }
	for _, err := range []error{
		&net.DNSError{Err: "no such host", Name: "server.example", IsNotFound: true},
		fmt.Errorf("TCP/TLS check failed: %w", &net.DNSError{Err: "no such host", Name: "server.example"}),
		errors.New("endpoint_dns_failed"),
		accesskey.ErrSSConfDNS,
	} {
		got := withKillSwitchHint(err, yes, yes)
		if !errors.Is(got, err) || !strings.Contains(got.Error(), "system DNS client") {
			t.Fatalf("missing DNS hint for %v: %v", err, got)
		}
		if got := withKillSwitchHint(err, no, no); got != err {
			t.Fatalf("DNS hint without protection: %v", got)
		}
	}
	dial := &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("blocked")}
	if got := withKillSwitchHint(dial, no, yes); strings.Contains(got.Error(), "system DNS client") || !strings.Contains(got.Error(), "elevated administrator terminal") {
		t.Fatalf("connection failure got the wrong hint: %v", got)
	}
}
