//go:build linux || darwin

package geofile

import (
	"golang.org/x/sys/unix"
	"path/filepath"
	"testing"
)

func TestRejectFIFO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data")
	if err := unix.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	if f, err := Open(path); err == nil {
		f.Close()
		t.Fatal("accepted FIFO")
	}
}
