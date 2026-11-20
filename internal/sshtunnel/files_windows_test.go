package sshtunnel

import (
	"testing"

	"golang.org/x/crypto/ssh/knownhosts"
)

func TestNewRejectsNonLocalPaths(t *testing.T) {
	hosts := writeHosts(t, knownhosts.Line([]string{"example.com:22"}, hostSigner(t).PublicKey()))
	for _, file := range []string{`\\server\share\known_hosts`, `\\.\pipe\bimeron-test`, `\\?\C:\known_hosts`} {
		checkFileRejected(t, Options{}, "", file, "SSH known_hosts unavailable: "+file)
		checkFileRejected(t, Options{}, file, hosts, "SSH identity file unavailable")
	}
}
