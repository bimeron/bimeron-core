package safefile

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestRead(t *testing.T) {
	dir := t.TempDir()
	file := func(name string, size int) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, bytes.Repeat([]byte("a"), size), 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	for name, tc := range map[string]struct {
		path string
		size int
		err  error
	}{
		"regular":   {file("regular", 8), 8, nil},
		"empty":     {file("empty", 0), 0, nil},
		"at limit":  {file("limit", 16), 16, nil},
		"oversized": {file("large", 17), 0, ErrTooLarge},
		"directory": {dir, 0, ErrNotRegular},
		"missing":   {filepath.Join(dir, "missing"), 0, os.ErrNotExist},
	} {
		t.Run(name, func(t *testing.T) {
			b, err := Read(tc.path, 16)
			if !errors.Is(err, tc.err) || err == nil && len(b) != tc.size {
				t.Fatalf("Read() = %d bytes, %v; want %d bytes, %v", len(b), err, tc.size, tc.err)
			}
		})
	}
}

func TestReadFollowsSymlinkToRegularFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	if b, err := Read(link, 16); err != nil || string(b) != "data" {
		t.Fatalf("Read() = %q, %v", b, err)
	}
	if err := os.Symlink(dir, filepath.Join(dir, "dirlink")); err == nil {
		if _, err := Read(filepath.Join(dir, "dirlink"), 16); !errors.Is(err, ErrNotRegular) {
			t.Fatalf("Read(directory link) = %v", err)
		}
	}
}
