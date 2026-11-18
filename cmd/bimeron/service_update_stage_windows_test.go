//go:build windows

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// requireElevated skips tests that read a staged file back: its private DACL
// grants only SYSTEM and Administrators, so an unelevated reader would fail
// with access denied instead of the check under test.
func requireElevated(t *testing.T) {
	t.Helper()
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("reading a privately staged update requires elevation")
	}
}

func TestWindowsSourceSwapBeforeElevationIsRejected(t *testing.T) {
	requireElevated(t)
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
	if err := stageVerifiedUpdate(source, staged, hex.EncodeToString(want[:]), copyUpdateSource); err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatal("swapped source", err)
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
	if err := copyUpdateSource(link, filepath.Join(dir, "staged")); !errors.Is(err, errUpdateSourceLink) {
		t.Fatal("link source", err)
	}
}

func TestWindowsUpdateSourceErrorsNameTheCause(t *testing.T) {
	dir := t.TempDir()
	staged := filepath.Join(dir, "staged")
	if err := copyUpdateSource(dir, staged); !errors.Is(err, errUpdateSourceNotRegular) {
		t.Fatal("directory source", err)
	}
	for _, source := range []string{`\\localhost\C$\Windows\win.ini`, `\\?\` + filepath.Join(dir, "x"), `\\.\` + filepath.Join(dir, "x"), `relative\x`} {
		if err := copyUpdateSource(source, staged); !errors.Is(err, errUpdateSourceNotLocal) {
			t.Fatal("non-local source", source, err)
		}
	}
}

func TestWindowsFixedDriveFinalPath(t *testing.T) {
	system := os.Getenv("SystemDrive")
	if len(system) != 2 {
		t.Skip("SystemDrive unavailable")
	}
	for final, want := range map[string]bool{
		`\\?\` + system + `\Windows\win.ini`:                 true,
		`\\?\UNC\server\share\update.exe`:                    false,
		`\\?\UNC\localhost\C$\update.exe`:                    false,
		`\\?\Volume{00000000-0000-0000-0000-000000000000}\f`: false,
		`\\?\GLOBALROOT\Device\Mup\server\share\f`:           false,
		`\\?\` + system:                      false,
		`\\?\1:\update.exe`:                  false,
		system + `\Windows\win.ini`:          false,
		`\\.\` + system + `\Windows\win.ini`: false,
		``:                                   false,
	} {
		if got := fixedDriveFinalPath(final); got != want {
			t.Errorf("fixedDriveFinalPath(%q) = %t, want %t", final, got, want)
		}
	}
}

// TestWindowsUpdateSourceThroughRemoteDirectoryLinkIsRejected opens a local
// path whose directory is a symbolic link to the loopback administrative
// share, so the path text looks local while the handle is served over SMB.
func TestWindowsUpdateSourceThroughRemoteDirectoryLinkIsRejected(t *testing.T) {
	dir := t.TempDir()
	shared := filepath.Join(dir, "shared")
	if err := os.Mkdir(shared, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(shared, "update.exe"), []byte("verified"), 0600); err != nil {
		t.Fatal(err)
	}
	volume := filepath.VolumeName(shared)
	share := `\\localhost\` + volume[:1] + `$` + shared[len(volume):]
	if _, err := os.Stat(filepath.Join(share, "update.exe")); err != nil {
		t.Skip("loopback administrative share unavailable:", err)
	}
	link := filepath.Join(dir, "remote")
	if err := os.Symlink(share, link); err != nil {
		t.Skip("directory symlink creation unavailable:", err)
	}
	source := filepath.Join(link, "update.exe")
	if _, err := os.Stat(source); err != nil {
		t.Skip("local-to-remote symlink evaluation unavailable:", err)
	}
	// Each handle check identifies the file as remote on its own.
	if final, remoteErr := handleLocality(t, source); remoteErr != nil || fixedDriveFinalPath(final) {
		t.Fatalf("remote handle not detected: protocol query %v, final path %q", remoteErr, final)
	}
	staged := filepath.Join(dir, "staged")
	if err := copyUpdateSource(source, staged); !errors.Is(err, errUpdateSourceNotLocal) {
		t.Fatal("source through remote link", err)
	}
	if _, err := os.Lstat(staged); !os.IsNotExist(err) {
		t.Fatal("staged file created", err)
	}
}

// handleLocality reports the remote-protocol query result and the final path
// of path, the two facts checkUpdateSourceLocal relies on.
func handleLocality(t *testing.T, path string) (final string, remoteErr error) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	h := windows.Handle(f.Fd())
	buf := make([]uint16, 1024)
	n, err := windows.GetFinalPathNameByHandle(h, &buf[0], uint32(len(buf)), fileNameNormalized|volumeNameDOS)
	if err != nil || n >= uint32(len(buf)) {
		t.Fatal("final path", n, err)
	}
	return windows.UTF16ToString(buf[:n]), remoteProtocolInfo(h)
}

func TestWindowsLocalUpdateSourceHandleIsLocal(t *testing.T) {
	source := filepath.Join(t.TempDir(), "download.exe")
	if err := os.WriteFile(source, []byte("verified"), 0600); err != nil {
		t.Fatal(err)
	}
	if final, remoteErr := handleLocality(t, source); remoteErr == nil || !fixedDriveFinalPath(final) {
		t.Fatalf("local handle not recognized: protocol query %v, final path %q", remoteErr, final)
	}
	f, err := openUpdateSource(source)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
}

// setTestReparsePoint attaches a third-party reparse tag, which no filter
// handles, to an existing file or directory while keeping its data.
func setTestReparsePoint(t *testing.T, path string, tag uint32) {
	t.Helper()
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(name, windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	// REPARSE_GUID_DATA_BUFFER: tag, data length, reserved, GUID, data.
	var buf [24 + 4]byte
	*(*uint32)(unsafe.Pointer(&buf[0])) = tag
	*(*uint16)(unsafe.Pointer(&buf[4])) = 4
	copy(buf[8:24], "bimeron-test-tag")
	var n uint32
	if err := windows.DeviceIoControl(h, windows.FSCTL_SET_REPARSE_POINT, &buf[0], uint32(len(buf)), nil, 0, &n, nil); err != nil {
		t.Skip("setting a reparse point unavailable:", err)
	}
}

// testReparseTag is a third-party tag without the name-surrogate bit, like
// cloud-file placeholders or deduplicated files.
const testReparseTag = 0x00000b1e

func TestWindowsUpdateSourceReparseDataFileIsAccepted(t *testing.T) {
	requireElevated(t)
	dir := t.TempDir()
	source, staged := filepath.Join(dir, "download.exe"), filepath.Join(dir, "protected.update-new")
	if err := os.WriteFile(source, []byte("verified"), 0600); err != nil {
		t.Fatal(err)
	}
	setTestReparsePoint(t, source, testReparseTag)
	want := sha256.Sum256([]byte("verified"))
	if err := stageVerifiedUpdate(source, staged, hex.EncodeToString(want[:]), copyUpdateSource); err != nil {
		t.Fatal("non-surrogate reparse data file", err)
	}
}

func TestWindowsUpdateSourceNameSurrogateIsRejected(t *testing.T) {
	dir := t.TempDir()
	source, staged := filepath.Join(dir, "download.exe"), filepath.Join(dir, "staged")
	if err := os.WriteFile(source, []byte("verified"), 0600); err != nil {
		t.Fatal(err)
	}
	setTestReparsePoint(t, source, reparseTagNameSurrogate|testReparseTag)
	if err := copyUpdateSource(source, staged); !errors.Is(err, errUpdateSourceLink) {
		t.Fatal("name-surrogate reparse file", err)
	}
	directory := filepath.Join(dir, "directory")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	setTestReparsePoint(t, directory, reparseTagNameSurrogate|testReparseTag)
	// A directory does not open without backup semantics, so the open itself
	// refuses it before the reparse tag is read.
	if err := copyUpdateSource(directory, staged); !errors.Is(err, errUpdateSourceNotRegular) {
		t.Fatal("name-surrogate reparse directory", err)
	}
	if _, err := os.Lstat(staged); !os.IsNotExist(err) {
		t.Fatal("staged file created", err)
	}
}

func TestWindowsStaleStagedUpdateIsReplaced(t *testing.T) {
	requireElevated(t)
	dir := t.TempDir()
	source, staged := filepath.Join(dir, "download.exe"), filepath.Join(dir, "protected.update-new")
	if err := os.WriteFile(source, []byte("verified"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staged, []byte("left by an interrupted update"), 0600); err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256([]byte("verified"))
	if err := stageVerifiedUpdate(source, staged, hex.EncodeToString(want[:]), copyUpdateSource); err != nil {
		t.Fatal(err)
	}
	if got := stagedDACL(t, staged); got != stagedUpdateSDDL {
		t.Fatal("replaced staged DACL", got)
	}
}

func TestWindowsUpdateSourceSizeAndDigestFailuresRemoveStaged(t *testing.T) {
	requireElevated(t)
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
	if err := stageVerifiedUpdate(source, staged, strings.Repeat("0", 64), copyUpdateSource); err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatal("digest mismatch", err)
	}
	if _, err := os.Lstat(staged); !os.IsNotExist(err) {
		t.Fatal("mismatched staged file kept", err)
	}
	if err := stageVerifiedUpdate(source, staged, hex.EncodeToString(want[:]), copyUpdateSource); err != nil {
		t.Fatal(err)
	}
}

// Go marks its processes long-path aware, so a plain drive-letter path longer
// than MAX_PATH is opened directly.
func TestWindowsUpdateSourceLongPath(t *testing.T) {
	dir := t.TempDir()
	for len(dir) <= windows.MAX_PATH {
		dir = filepath.Join(dir, strings.Repeat("d", 60))
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(dir, "download.exe")
	if err := os.WriteFile(source, []byte("verified"), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := openUpdateSource(source)
	if err != nil {
		t.Fatalf("%d-character source: %v", len(source), err)
	}
	f.Close()
}
