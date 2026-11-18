package safefile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestReadRejectsNonLocalWindowsPaths(t *testing.T) {
	dir := t.TempDir()
	regular := filepath.Join(dir, "regular")
	if err := os.WriteFile(regular, []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		`\\server\share\profile.conf`,
		`//server/share/profile.conf`,
		`\/server\share\profile.conf`,
		`\\localhost\C$\profile.conf`,
		`\\?\` + regular,
		`\\?\UNC\server\share\profile.conf`,
		`\\.\pipe\bimeron-test`,
		`\\.\C:`,
		`\??\` + regular,
		`NUL`,
		`C:\NUL`,
		filepath.Join(dir, "CON"),
		filepath.Join(dir, "com1.txt"),
		filepath.Join(dir, "LPT1"),
		filepath.Join(dir, "CONOUT$"),
		regular + ":stream",
	} {
		if _, err := Read(path, 16); !errors.Is(err, ErrNotLocal) {
			t.Errorf("Read(%q) = %v", path, err)
		}
	}
	for _, path := range []string{regular, dir + `\.\regular`, dir + `\x\..\regular`, "/" + filepath.ToSlash(regular)[3:]} {
		if b, err := Read(path, 16); err != nil || string(b) != "data" {
			t.Errorf("Read(%q) = %q, %v", path, b, err)
		}
	}
}
