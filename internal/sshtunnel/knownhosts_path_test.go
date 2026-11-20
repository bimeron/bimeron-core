package sshtunnel

import (
	"errors"
	"net"
	"strings"
	"testing"

	bknownhosts "bimeron/internal/sshtunnel/knownhosts"
	"golang.org/x/crypto/ssh/knownhosts"
)

// TestKnownHostsNamesFile checks that parse errors and host key mismatches
// name the known_hosts file that was read.
func TestKnownHostsNamesFile(t *testing.T) {
	path := writeHosts(t, knownhosts.Line([]string{"example.com:22"}, hostSigner(t).PublicKey()))
	verify, _, err := knownHosts(path)
	if err != nil {
		t.Fatal(err)
	}
	remote := &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 22}
	var ke *bknownhosts.KeyError
	if err := verify("example.com:22", remote, hostSigner(t).PublicKey()); !errors.As(err, &ke) || len(ke.Want) != 1 || ke.Want[0].Filename != path {
		t.Fatalf("mismatch = %v, want a key error naming %s", err, path)
	}

	bad := writeHosts(t, "example.com ssh-ed25519 not-base64")
	if _, _, err := knownHosts(bad); err == nil || !strings.Contains(err.Error(), bad+":1:") {
		t.Fatalf("parse error = %v, want it to name %s", err, bad)
	}
}
