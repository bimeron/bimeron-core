package safefile

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
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
		filepath.Join(dir, "COM1"),
		filepath.Join(dir, "LPT1"),
		filepath.Join(dir, "CONOUT$"),
		regular + ":stream",
		"C:profile.conf",
		"C:",
		filepath.VolumeName(regular) + "regular",
	} {
		if _, err := Read(path, 16); !errors.Is(err, ErrNotLocal) {
			t.Errorf("Read(%q) = %v", path, err)
		}
	}
	valid := []string{regular, dir + `\.\regular`, dir + `\x\..\regular`}
	// A rooted path without a drive resolves against the current drive.
	if wd, err := os.Getwd(); err == nil && strings.EqualFold(filepath.VolumeName(wd), filepath.VolumeName(regular)) {
		valid = append(valid, "/"+filepath.ToSlash(regular)[3:])
	}
	for _, path := range valid {
		if b, err := Read(path, 16); err != nil || string(b) != "data" {
			t.Errorf("Read(%q) = %q, %v", path, b, err)
		}
	}
}
