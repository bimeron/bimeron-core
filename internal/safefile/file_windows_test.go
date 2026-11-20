package safefile

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

const (
	reparseTagCloud = 0x9000401a
	reparseTagDedup = 0x80000013
)

func TestRegularMode(t *testing.T) {
	for mode, want := range map[fs.FileMode]bool{
		0:                                 true,
		0444:                              true,
		fs.ModeIrregular:                  true, // cloud files and other data reparse points
		fs.ModeDir:                        false,
		fs.ModeDir | fs.ModeIrregular:     false,
		fs.ModeNamedPipe:                  false,
		fs.ModeDevice | fs.ModeCharDevice: false,
		fs.ModeSocket:                     false,
		fs.ModeSymlink:                    false,
	} {
		if got := regular(mode); got != want {
			t.Errorf("regular(%v) = %v, want %v", mode, got, want)
		}
	}
}

func TestCheckKind(t *testing.T) {
	const (
		disk    = windows.FILE_TYPE_DISK
		reparse = windows.FILE_ATTRIBUTE_REPARSE_POINT
		dir     = windows.FILE_ATTRIBUTE_DIRECTORY
	)
	for _, tc := range []struct {
		name                 string
		fileType, attrs, tag uint32
		ok                   bool
	}{
		{"file", disk, windows.FILE_ATTRIBUTE_ARCHIVE, 0, true},
		{"cloud file", disk, reparse | windows.FILE_ATTRIBUTE_ARCHIVE, reparseTagCloud, true},
		{"dedup file", disk, reparse, reparseTagDedup, true},
		{"cloud directory", disk, reparse | dir, reparseTagCloud, false},
		{"directory", disk, dir, 0, false},
		{"symbolic link", disk, reparse, windows.IO_REPARSE_TAG_SYMLINK, false},
		{"mount point", disk, reparse | dir, windows.IO_REPARSE_TAG_MOUNT_POINT, false},
		{"socket", disk, reparse, reparseTagAFUnix, false},
		{"WSL symbolic link", disk, reparse, 0xa000001d, false},
		{"WSL FIFO", disk, reparse, reparseTagLXFIFO, false},
		{"WSL character device", disk, reparse, reparseTagLXChr, false},
		{"WSL block device", disk, reparse, reparseTagLXBlk, false},
		{"tag without reparse attribute", disk, windows.FILE_ATTRIBUTE_ARCHIVE, reparseTagLXFIFO, true},
		{"pipe", windows.FILE_TYPE_PIPE, 0, 0, false},
		{"device", windows.FILE_TYPE_CHAR, 0, 0, false},
		{"unknown", windows.FILE_TYPE_UNKNOWN, 0, 0, false},
	} {
		err := checkKind(tc.fileType, tc.attrs, tc.tag)
		if tc.ok && err != nil || !tc.ok && !errors.Is(err, ErrNotRegular) {
			t.Errorf("%s: checkKind() = %v", tc.name, err)
		}
	}
}

// stubHandleQueries replaces the handle queries for one test.
func stubHandleQueries(t *testing.T, attributes uint32, tagErr error) *int {
	t.Helper()
	oldInfo, oldTag := getFileInformation, getAttributeTag
	t.Cleanup(func() { getFileInformation, getAttributeTag = oldInfo, oldTag })
	tagQueries := 0
	getFileInformation = func(_ windows.Handle, info *windows.ByHandleFileInformation) error {
		info.FileAttributes = attributes
		return nil
	}
	getAttributeTag = func(_ windows.Handle, info *fileAttributeTagInfo) error {
		tagQueries++
		if tagErr != nil {
			return tagErr
		}
		info.FileAttributes, info.ReparseTag = attributes, reparseTagCloud
		return nil
	}
	return &tagQueries
}

func TestAttributeTagQueriesTagOnlyForReparsePoints(t *testing.T) {
	queries := stubHandleQueries(t, windows.FILE_ATTRIBUTE_ARCHIVE, windows.ERROR_INVALID_PARAMETER)
	if attributes, tag, _, err := attributeTag(0); err != nil || attributes != windows.FILE_ATTRIBUTE_ARCHIVE || tag != 0 || *queries != 0 {
		t.Fatalf("plain file: attributes %#x, tag %#x, %v after %d tag queries", attributes, tag, err, *queries)
	}

	queries = stubHandleQueries(t, windows.FILE_ATTRIBUTE_REPARSE_POINT, nil)
	if _, tag, _, err := attributeTag(0); err != nil || tag != reparseTagCloud || *queries != 1 {
		t.Fatalf("reparse point: tag %#x, %v after %d tag queries", tag, err, *queries)
	}

	stubHandleQueries(t, windows.FILE_ATTRIBUTE_REPARSE_POINT, windows.ERROR_INVALID_PARAMETER)
	if _, _, op, err := attributeTag(0); !errors.Is(err, windows.ERROR_INVALID_PARAMETER) || op != "GetFileInformationByHandleEx" {
		t.Fatalf("failed tag query: %s, %v", op, err)
	}
}

// TestCheckOpenedWithoutTagQuery reads a local file on a file system that
// does not implement FileAttributeTagInfo.
func TestCheckOpenedWithoutTagQuery(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	old := getAttributeTag
	t.Cleanup(func() { getAttributeTag = old })
	getAttributeTag = func(windows.Handle, *fileAttributeTagInfo) error { return windows.ERROR_INVALID_PARAMETER }
	if b, err := Read(file, 16); err != nil || string(b) != "data" {
		t.Fatalf("Read() = %q, %v", b, err)
	}
}

func TestUNCFinalPath(t *testing.T) {
	for path, want := range map[string]bool{
		`\\?\UNC\server\share\file`: true,
		`\\?\unc\server\share\file`: true,
		`\\?\C:\file`:               false,
		`\\?\UNC`:                   false,
		``:                          false,
	} {
		if got := uncFinalPath(path); got != want {
			t.Errorf("uncFinalPath(%q) = %v", path, got)
		}
	}
}

// checkOpenedPath opens path without the checks of Read and runs the handle
// check on it.
func checkOpenedPath(t *testing.T, path string) error {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Skipf("open %s: %v", path, err)
	}
	defer f.Close()
	return checkOpened(f)
}

func TestCheckOpenedHandles(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := checkOpenedPath(t, file); err != nil {
		t.Errorf("local file: %v", err)
	}
	for _, path := range []string{dir, `\\.\NUL`} {
		if err := checkOpenedPath(t, path); !errors.Is(err, ErrNotRegular) {
			t.Errorf("%s: %v", path, err)
		}
	}
}

func TestCheckOpenedRejectsPipe(t *testing.T) {
	name := `\\.\pipe\bimeron-safefile-test`
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		t.Fatal(err)
	}
	server, err := windows.CreateNamedPipe(p, windows.PIPE_ACCESS_DUPLEX, windows.PIPE_TYPE_BYTE, 1, 512, 512, 0, nil)
	if err != nil {
		t.Skip("named pipe unavailable:", err)
	}
	defer windows.CloseHandle(server)
	if err := checkOpenedPath(t, name); !errors.Is(err, ErrNotRegular) {
		t.Errorf("pipe: %v", err)
	}
}

// TestCheckOpenedRejectsRemote opens a file through the administrative share
// of the local computer, which reaches it through the network redirector.
func TestCheckOpenedRejectsRemote(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	volume := filepath.VolumeName(file)
	if len(volume) != 2 {
		t.Skip("temporary directory has no drive letter")
	}
	share := `\\localhost\` + volume[:1] + `$` + file[2:]
	if err := checkOpenedPath(t, share); !errors.Is(err, ErrNotLocal) {
		t.Errorf("%s: %v", share, err)
	}
}

// TestReadCloudFile reads a OneDrive cloud file named by
// BIMERON_TEST_CLOUD_FILE. Such a file needs a signed-in OneDrive account, so
// the test is skipped without it.
func TestReadCloudFile(t *testing.T) {
	path := os.Getenv("BIMERON_TEST_CLOUD_FILE")
	if path == "" {
		t.Skip("BIMERON_TEST_CLOUD_FILE is not set")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Type() != fs.ModeIrregular {
		t.Fatalf("%s has mode %v, want a cloud file", path, info.Mode())
	}
	limit := info.Size()
	if b, err := Read(path, limit); err != nil || int64(len(b)) != limit {
		t.Fatalf("Read() = %d bytes, %v", len(b), err)
	}
}
