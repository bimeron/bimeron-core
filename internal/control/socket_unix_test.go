//go:build linux || darwin

package control

import (
	"context"
	"net"
	"os"
	"path/filepath"
	core "bimeron/core"
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
