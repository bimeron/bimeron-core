//go:build linux

package linuxnet

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExclusiveLockAndSymlinkRefusal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "daemon.lock")
	release, err := lockFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if duplicate, err := lockFile(path); err == nil {
		duplicate()
		release()
		t.Fatal("second daemon acquired lock")
	}
	release()
	release, err = lockFile(path)
	if err != nil {
		t.Fatal("lock not released", err)
	}
	release()
	if err := os.Symlink(path, filepath.Join(dir, "alias.lock")); err != nil {
		t.Fatal(err)
	}
	if release, err := lockFile(filepath.Join(dir, "alias.lock")); err == nil {
		release()
		t.Fatal("followed lock symlink")
	}
}
