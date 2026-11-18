//go:build linux || darwin

package safefile

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestReadRejectsSpecialFilesWithoutBlocking(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "fifo")
	if err := unix.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{fifo, "/dev/null", "/dev/zero"} {
		done := make(chan error, 1)
		go func() {
			_, err := Read(path, 16)
			done <- err
		}()
		select {
		case err := <-done:
			if !errors.Is(err, ErrNotRegular) {
				t.Errorf("Read(%s) = %v", path, err)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("Read(%s) blocked", path)
		}
	}
}
