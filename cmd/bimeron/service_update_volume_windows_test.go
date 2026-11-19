//go:build windows

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsVolumeGUIDRoot(t *testing.T) {
	const guid = `\\?\Volume{0b1e0000-0000-0000-0000-000000000001}`
	for final, want := range map[string]string{
		guid + `\Users\update.exe`:            guid + `\`,
		strings.ToLower(guid) + `\update.exe`: strings.ToLower(guid) + `\`,
		guid:                                  guid + `\`,
		guid + `x\update.exe`:                 "",
		`\\?\Volume{0b1e`:                     "",
		`\\?\C:\update.exe`:                   "",
		`\\?\UNC\server\share\update.exe`:     "",
		`\\?\GLOBALROOT\Device\HarddiskVolume1\update.exe`: "",
		`\Device\HarddiskVolume1\update.exe`:               "",
		``:                                                 "",
	} {
		root, ok := volumeGUIDRoot(final)
		if root != want || ok != (want != "") {
			t.Errorf("volumeGUIDRoot(%q) = %q, %t; want %q", final, root, ok, want)
		}
	}
}

// openForVolume opens path for attributes and returns the handle.
func openForVolume(t *testing.T, path string) windows.Handle {
	t.Helper()
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(name, windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { windows.CloseHandle(h) })
	return h
}

func volumeRootOf(t *testing.T, h windows.Handle) string {
	t.Helper()
	final, err := finalPathName(h, fileNameNormalized|volumeNameGUID)
	if err != nil {
		t.Fatal(err)
	}
	root, ok := volumeGUIDRoot(final)
	if !ok {
		t.Fatalf("no volume GUID root in %q", final)
	}
	return root
}

// TestWindowsFixedVolume checks the volume of an opened file. With
// BIMERON_TEST_MOUNTED_FOLDER naming a writable folder where another volume is
// mounted, a file there must resolve to that volume, not to the drive that
// holds the folder; BIMERON_TEST_MOUNTED_FOLDER_FIXED=0 says that volume is
// not a fixed drive.
func TestWindowsFixedVolume(t *testing.T) {
	system := os.Getenv("SystemRoot")
	if system == "" {
		t.Skip("SystemRoot unavailable")
	}
	systemFile := openForVolume(t, filepath.Join(system, "win.ini"))
	if !fixedVolume(systemFile) {
		t.Fatal("system drive volume is not fixed")
	}
	mounted := os.Getenv("BIMERON_TEST_MOUNTED_FOLDER")
	if mounted == "" {
		return
	}
	file := filepath.Join(mounted, "bimeron-volume-test.exe")
	if err := os.WriteFile(file, []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(file) })
	h := openForVolume(t, file)
	if a, b := volumeRootOf(t, h), volumeRootOf(t, systemFile); strings.EqualFold(a, b) {
		t.Fatalf("file in the mounted folder resolves to the system volume %s", a)
	}
	want := os.Getenv("BIMERON_TEST_MOUNTED_FOLDER_FIXED") != "0"
	if got := fixedVolume(h); got != want {
		t.Fatalf("fixedVolume(mounted folder file) = %t, want %t", got, want)
	}
	if want {
		if err := checkUpdateSourceLocal(h); err != nil {
			t.Fatalf("checkUpdateSourceLocal(mounted folder file) = %v", err)
		}
	} else if err := checkUpdateSourceLocal(h); err != errUpdateSourceNotLocal {
		t.Fatalf("checkUpdateSourceLocal(mounted folder file) = %v, want not local", err)
	}
}
