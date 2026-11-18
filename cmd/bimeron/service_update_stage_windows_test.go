//go:build windows

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsSourceSwapBeforeElevationIsRejected(t *testing.T) {
	dir := t.TempDir()
	source, staged := filepath.Join(dir, "download.exe"), filepath.Join(dir, "protected.update-new")
	want := sha256.Sum256([]byte("verified"))
	if err := os.WriteFile(source, []byte("verified"), 0600); err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(dir, "replacement.exe")
	if err := os.WriteFile(replacement, []byte("swapped"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(source); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, source); err != nil {
		t.Fatal(err)
	}
	if err := stageVerifiedUpdate(source, staged, hex.EncodeToString(want[:]), copyUpdateSource); err == nil {
		t.Fatal("swapped source accepted")
	}
}

func stagedDACL(t *testing.T, path string) string {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	return sd.String()
}

func TestWindowsUpdateSourceIsStagedPrivately(t *testing.T) {
	dir := t.TempDir()
	source, staged := filepath.Join(dir, "download.exe"), filepath.Join(dir, "protected.update-new")
	if err := os.WriteFile(source, []byte("verified"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := copyUpdateSource(source, staged); err != nil {
		t.Fatal(err)
	}
	if got := stagedDACL(t, staged); got != "D:P(A;;FA;;;SY)(A;;FA;;;BA)" {
		t.Fatal("staged DACL", got)
	}
	if err := inheritServiceFileACL(staged); err != nil {
		t.Fatal(err)
	}
	if got := stagedDACL(t, staged); strings.HasPrefix(got, "D:P") || !strings.Contains(got, ";ID;") {
		t.Fatal("verified DACL is not inherited", got)
	}
	if b, err := os.ReadFile(staged); err != nil || string(b) != "verified" {
		t.Fatal(string(b), err)
	}
}

func TestWindowsUpdateSourceRejectsLinksAndNonFiles(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.exe")
	if err := os.WriteFile(target, []byte("verified"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{dir, `\\localhost\C$\Windows\win.ini`, `\\?\` + target, `\\.\` + target, filepath.Join(dir, "NUL")} {
		if err := copyUpdateSource(source, filepath.Join(dir, "staged")); err == nil {
			t.Fatal("accepted", source)
		}
	}
	if _, err := os.Lstat(filepath.Join(dir, "staged")); !os.IsNotExist(err) {
		t.Fatal("staged file created", err)
	}
	link := filepath.Join(dir, "link.exe")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("symlink creation unavailable:", err)
	}
	if err := copyUpdateSource(link, filepath.Join(dir, "staged")); err != errUpdateSourceNotRegular {
		t.Fatal("link source", err)
	}
}

func TestWindowsUpdateSourceSizeAndDigestFailuresRemoveStaged(t *testing.T) {
	dir := t.TempDir()
	source, staged := filepath.Join(dir, "download.exe"), filepath.Join(dir, "protected.update-new")
	if err := os.WriteFile(source, []byte("verified"), 0600); err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256([]byte("verified"))
	defer func(limit int64) { maxUpdateSourceSize = limit }(maxUpdateSourceSize)
	maxUpdateSourceSize = 7
	if err := stageVerifiedUpdate(source, staged, hex.EncodeToString(want[:]), copyUpdateSource); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatal("oversized source", err)
	}
	if _, err := os.Lstat(staged); !os.IsNotExist(err) {
		t.Fatal("oversized staged file kept", err)
	}
	maxUpdateSourceSize = 8
	if err := stageVerifiedUpdate(source, staged, strings.Repeat("0", 64), copyUpdateSource); err == nil {
		t.Fatal("digest mismatch accepted")
	}
	if _, err := os.Lstat(staged); !os.IsNotExist(err) {
		t.Fatal("mismatched staged file kept", err)
	}
	if err := stageVerifiedUpdate(source, staged, hex.EncodeToString(want[:]), copyUpdateSource); err != nil {
		t.Fatal(err)
	}
}
