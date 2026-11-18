//go:build linux || darwin

package masque

import (
	"net"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestNewRejectsSpecialCAFile(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "fifo")
	if err := unix.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{fifo, "/dev/zero"} {
		done := make(chan error, 1)
		go func() {
			c, err := New(masqueWithCA(t, path), net.Dialer{})
			if c != nil {
				c.Close()
			}
			done <- err
		}()
		select {
		case err := <-done:
			if err == nil || err.Error() != "could not read MASQUE CA file" {
				t.Errorf("CAFile %s: error = %v", path, err)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("CAFile %s: blocked", path)
		}
	}
}
