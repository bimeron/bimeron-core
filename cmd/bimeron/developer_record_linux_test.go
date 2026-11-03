//go:build linux

package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestDeveloperEndpointCredentials(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peer.sock")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	c, err := (&net.Dialer{}).DialContext(context.Background(), "unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for _, tc := range []struct {
		pid, uid uint32
		want     bool
	}{{uint32(os.Getpid()), uint32(os.Getuid()), true}, {uint32(os.Getpid() + 1), uint32(os.Getuid()), false}, {uint32(os.Getpid()), uint32(os.Getuid() + 1), false}} {
		if got := developerEndpointMatches(c, tc.pid, tc.uid); got != tc.want {
			t.Fatalf("credentials accepted=%v want=%v", got, tc.want)
		}
	}
}

func TestDeveloperImageReplacementRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "exe")
	if err := os.WriteFile(path, []byte("image"), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	pinned, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if !developerImageMatches(pinned, path) {
		t.Fatal("same image rejected")
	}
	if err := os.Rename(path, path+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("image"), 0600); err != nil {
		t.Fatal(err)
	}
	if developerImageMatches(pinned, path) {
		t.Fatal("replacement with identical bytes accepted")
	}
	os.Remove(path)
	if developerImageMatches(pinned, path) {
		t.Fatal("missing process image accepted")
	}
}
