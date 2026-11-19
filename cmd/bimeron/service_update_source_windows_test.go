//go:build windows

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestWindowsUpdateSourceJunctionIsALink(t *testing.T) {
	dir := t.TempDir()
	target, junction := filepath.Join(dir, "target"), filepath.Join(dir, "junction")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", junction, target).CombinedOutput(); err != nil {
		t.Skipf("junction creation unavailable: %v: %s", err, out)
	}
	if err := copyUpdateSource(junction, filepath.Join(dir, "staged")); !errors.Is(err, errUpdateSourceLink) {
		t.Fatal("junction source", err)
	}
	if err := copyUpdateSource(target, filepath.Join(dir, "staged")); !errors.Is(err, errUpdateSourceNotRegular) {
		t.Fatal("directory source", err)
	}
}

// setMicrosoftReparsePoint attaches a Microsoft reparse tag without data, as
// WSL uses for FIFOs and device files.
func setMicrosoftReparsePoint(t *testing.T, path string, tag uint32) {
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
	// REPARSE_DATA_BUFFER header: tag, data length, reserved.
	var buf [8]byte
	*(*uint32)(unsafe.Pointer(&buf[0])) = tag
	var n uint32
	if err := windows.DeviceIoControl(h, windows.FSCTL_SET_REPARSE_POINT, &buf[0], uint32(len(buf)), nil, 0, &n, nil); err != nil {
		t.Skip("setting a reparse point unavailable:", err)
	}
}

func TestWindowsUpdateSourceSpecialFilesAreRejected(t *testing.T) {
	for _, tag := range []uint32{reparseTagAFUnix, reparseTagLXFIFO, reparseTagLXChr, reparseTagLXBlk} {
		if !specialFileTag(tag) {
			t.Errorf("specialFileTag(%#x) = false", tag)
		}
	}
	if specialFileTag(testReparseTag) || specialFileTag(0x9000401a) || specialFileTag(windows.IO_REPARSE_TAG_SYMLINK) {
		t.Error("other reparse tag treated as a special file")
	}
	dir := t.TempDir()
	for name, tag := range map[string]uint32{"fifo": reparseTagLXFIFO, "chr": reparseTagLXChr, "blk": reparseTagLXBlk, "socket": reparseTagAFUnix} {
		source := filepath.Join(dir, name)
		if err := os.WriteFile(source, nil, 0600); err != nil {
			t.Fatal(err)
		}
		setMicrosoftReparsePoint(t, source, tag)
		if err := copyUpdateSource(source, filepath.Join(dir, "staged")); !errors.Is(err, errUpdateSourceNotRegular) {
			t.Errorf("%s source: %v", name, err)
		}
	}
}

// TestWindowsVolumePath checks the volume mount point used for the drive type.
// With BIMERON_TEST_MOUNTED_FOLDER naming a folder where another volume is
// mounted, a file in it must resolve to that folder, not to its drive;
// BIMERON_TEST_MOUNTED_FOLDER_FIXED=0 says that volume is not a fixed drive.
func TestWindowsVolumePath(t *testing.T) {
	system := os.Getenv("SystemDrive")
	if len(system) != 2 {
		t.Skip("SystemDrive unavailable")
	}
	for _, path := range []string{system + `\Windows\win.ini`, `\\?\` + system + `\Windows\win.ini`} {
		volume, err := volumePath(path)
		if err != nil || !strings.EqualFold(strings.TrimPrefix(volume, `\\?\`), system+`\`) {
			t.Errorf("volumePath(%q) = %q, %v", path, volume, err)
		}
		if !fixedVolume(path) {
			t.Errorf("fixedVolume(%q) = false", path)
		}
	}
	mounted := os.Getenv("BIMERON_TEST_MOUNTED_FOLDER")
	if mounted == "" {
		return
	}
	mounted = strings.TrimRight(mounted, `\`)
	file := `\\?\` + mounted + `\update.exe`
	volume, err := volumePath(file)
	if err != nil || !strings.EqualFold(strings.TrimPrefix(volume, `\\?\`), mounted+`\`) {
		t.Fatalf("volumePath(%q) = %q, %v; want the mounted folder", file, volume, err)
	}
	want := os.Getenv("BIMERON_TEST_MOUNTED_FOLDER_FIXED") != "0"
	if got := fixedVolume(file); got != want {
		t.Fatalf("fixedVolume(%q) = %t, want %t", file, got, want)
	}
}
