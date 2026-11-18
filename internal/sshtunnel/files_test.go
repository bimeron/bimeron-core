package sshtunnel

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"bimeron/internal/accesskey"
	"golang.org/x/crypto/ssh/knownhosts"
)

// unusedServer returns an address whose listener fails the test on connect.
func unusedServer(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		if c, err := l.Accept(); err == nil {
			c.Close()
			t.Error("connected despite an unusable file")
		}
	}()
	return l.Addr().String()
}

// checkFileRejected connects with the given files and requires a timely
// failure before any connection.
func checkFileRejected(t *testing.T, o Options, identity, hosts, want string) {
	t.Helper()
	address := unusedServer(t)
	p, err := accesskey.ParseSSH("ssh://alice@" + address)
	if err != nil {
		t.Fatal(err)
	}
	p.SSH.IdentityFile, p.SSH.KnownHostsFile = identity, hosts
	done := make(chan error, 1)
	go func() {
		c, err := NewWithOptions(context.Background(), p, net.Dialer{}, nil, o)
		if c != nil {
			c.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || err.Error() != want {
			t.Errorf("identity %q, known_hosts %q: error = %v, want %q", identity, hosts, err, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("identity %q, known_hosts %q: blocked", identity, hosts)
	}
}

func TestNewRequiresRegularBoundedFiles(t *testing.T) {
	dir := t.TempDir()
	large := func(name string, size int) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, bytes.Repeat([]byte("#"), size), 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	hosts := writeHosts(t, knownhosts.Line([]string{"example.com:22"}, hostSigner(t).PublicKey()))
	for _, file := range []string{dir, large("known_hosts", maxKnownHostsFile+1)} {
		checkFileRejected(t, Options{}, "", file, "SSH known_hosts unavailable")
		checkFileRejected(t, Options{HostKeys: mustKeys(t, "")}, "", file, "SSH known_hosts unavailable")
	}
	for _, file := range []string{dir, large("id_ed25519", maxIdentityFile+1)} {
		checkFileRejected(t, Options{}, file, hosts, "SSH identity file unavailable")
	}
}
