//go:build linux || darwin

package control

import (
	core "bimeron/core"
	"context"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestNativeUnixSocket(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "bimeron-ipc-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "control.sock")
	var released atomic.Int32
	l, err := listenUnix(dir, path, uint32(os.Getuid()), func() { released.Add(1) })
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("unsafe socket permissions", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	e := &fakeEngine{state: core.Disconnected, events: make(chan core.Event)}
	go func() { done <- NewServer(e).Serve(ctx, l) }()
	for _, command := range []string{"status", "stop", "status", "shutdown"} {
		c, err := net.Dial("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		_, err = exchange(ctx, c, Request{Command: command})
		c.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("daemon did not exit")
	}
	if released.Load() != 1 {
		t.Fatal("daemon lock not released exactly once")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("stale socket retained")
	}
}

func TestControlOwnerUIDPrefersServiceOwner(t *testing.T) {
	t.Setenv("SUDO_UID", "1000")
	t.Setenv("BIMERON_CONTROL_UID", "2000")
	uid, err := controlOwnerUID()
	if err != nil || uid != 2000 {
		t.Fatal(uid, err)
	}
	t.Setenv("BIMERON_CONTROL_UID", "invalid")
	if _, err = controlOwnerUID(); err == nil {
		t.Fatal("invalid service owner accepted")
	}
}

func TestUnixServerIdentity(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "bimeron-ipc-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "control.sock")
	uid := uint32(os.Getuid())
	l, err := listenUnix(dir, path, uid, func() {})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if err := verifySocketPath(dir, path, uid); err != nil {
		t.Fatal("expected path accepted:", err)
	}
	if err := verifySocketPath(dir, path, uid+1); err != ErrServerUntrusted {
		t.Fatal("foreign directory owner accepted:", err)
	}
	link := dir + ".link"
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(link)
	if err := verifySocketPath(link, filepath.Join(link, "control.sock"), uid); err != ErrServerUntrusted {
		t.Fatal("symlinked directory accepted:", err)
	}
	plain := filepath.Join(dir, "plain")
	if err := os.WriteFile(plain, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifySocketPath(dir, plain, uid); err != ErrServerUntrusted {
		t.Fatal("non-socket accepted:", err)
	}
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatal(err)
	}
	if err := verifySocketPath(dir, path, uid); err != ErrServerUntrusted {
		t.Fatal("writable directory accepted:", err)
	}

	go func() {
		if c, err := l.Accept(); err == nil {
			c.Close()
		}
	}()
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	peer, err := peerUID(c.(*net.UnixConn))
	if err != nil || peer != uid {
		t.Fatalf("peer UID %d, %v; want %d", peer, err, uid)
	}
	if err := trustedServer(0, nil); err != nil {
		t.Fatal("root server rejected")
	}
	if err := trustedServer(0, os.ErrClosed); err != ErrServerUntrusted {
		t.Fatal("failed credential lookup accepted")
	}
	if uid != 0 && trustedServer(peer, nil) != ErrServerUntrusted {
		t.Fatal("non-root server accepted")
	}
}
