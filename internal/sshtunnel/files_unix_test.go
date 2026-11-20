//go:build linux || darwin

package sshtunnel

import (
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/sys/unix"
)

func TestNewRejectsSpecialFiles(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "fifo")
	if err := unix.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	hosts := writeHosts(t, knownhosts.Line([]string{"example.com:22"}, hostSigner(t).PublicKey()))
	for _, file := range []string{fifo, "/dev/zero"} {
		checkFileRejected(t, Options{}, "", file, "SSH known_hosts unavailable: "+file)
		checkFileRejected(t, Options{}, file, hosts, "SSH identity file unavailable")
	}
}
