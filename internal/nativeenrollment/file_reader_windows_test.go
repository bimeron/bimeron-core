//go:build windows

package nativeenrollment

import (
	"bytes"
	"errors"
	"golang.org/x/sys/windows"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestNativePathSyntax(t *testing.T) {
	for _, p := range []string{`relative`, `\\server\share`, `\\.\pipe\x`, `C:\a:stream`, `C:\a\..\b`, `C:\a.`, `C:\a `} {
		if _, _, e := nativeFolderParts(p); e == nil {
			t.Fatalf("accepted %q", p)
		}
	}
	root, parts, e := nativeFolderParts(`C:\Program Files`)
	if e != nil || root != `C:\` || len(parts) != 1 || parts[0] != "Program Files" {
		t.Fatal(root, parts, e)
	}
	for _, n := range []string{"", ".", "..", "a:b", `a\b`, "a/b", "a.", "a "} {
		if nativeComponent(n) {
			t.Fatalf("component %q", n)
		}
	}
	if !nativeVolumeRoot(`\\?\Volume{12345678-1234-1234-1234-123456789abc}\`) {
		t.Fatal("GUID root rejected")
	}
	for _, s := range []string{`C:\`, `\\server\share\`, `\\?\Volume{bad}\`} {
		if nativeVolumeRoot(s) {
			t.Fatal("invalid root accepted", s)
		}
	}
}

func TestBoundedNativeSamples(t *testing.T) {
	b, _ := Encode(fixture(Clean))
	for _, n := range []int{0, 48, 63, 65, 4096} {
		data := make([]byte, n)
		copy(data, []byte("LPF"))
		got, e := recordSample(bytes.NewReader(data))
		if n > 65 && len(got) > 65 {
			t.Fatal("unbounded sample")
		}
		if e != nil {
			t.Fatal(e)
		}
		if _, e = Decode(got); e == nil {
			t.Fatalf("accepted %d bytes", n)
		}
	}
	got, e := recordSample(bytes.NewReader(b))
	if e != nil || !bytes.Equal(got, b) {
		t.Fatal(e)
	}
	broken := failingRecordReader{}
	if _, e := recordSample(broken); e == nil {
		t.Fatal("read error accepted")
	}
	// These byte samples are codec/model evidence, never native trust evidence.
	o := present(fixture(Clean))
	o.Second.Bytes = bytes.Clone(b)
	o.Second.Bytes[16]++
	if Evaluate(o).Reason != ChangedSnapshot {
		t.Fatal("changed sample accepted")
	}
}

type failingRecordReader struct{}

func (failingRecordReader) ReadAt([]byte, int64) (int, error) {
	return 0, errors.New("fixture read failure")
}

var _ io.ReaderAt = failingRecordReader{}

func TestNativeDisposableRejectionAndPins(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "record.bin")
	if o := readNativeFolder(dir, nil); o.Result != UnsafeRead || Evaluate(o).Reason != UnsafeEvidence {
		t.Fatalf("disposable untrusted tree accepted: %+v", o)
	}
	b, _ := Encode(fixture(Clean))
	if e := os.WriteFile(path, b, 0600); e != nil {
		t.Fatal(e)
	}
	f, e := openNativePath(path, false)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = nativeIdentity(f, false); e != nil {
		t.Fatal(e)
	}
	if _, e = nativeIdentity(f, true); e == nil {
		t.Fatal("file accepted as directory")
	}
	if e := os.WriteFile(path, b, 0600); e == nil {
		t.Fatal("write sharing allowed")
	}
	if e := os.Remove(path); e == nil {
		t.Fatal("delete sharing allowed")
	}
	if e := closeNativeFiles([]*os.File{f}); e != nil {
		t.Fatal(e)
	}
	if e := closeNativeFiles([]*os.File{f}); e == nil {
		t.Fatal("cleanup failure hidden")
	}
	if _, e := nativeIdentity(f, false); e == nil {
		t.Fatal("closed handle accepted")
	}
	link := filepath.Join(dir, "alias.bin")
	if e := os.Link(path, link); e != nil {
		t.Fatal(e)
	}
	f, e = openNativePath(path, false)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := nativeIdentity(f, false); e == nil {
		f.Close()
		t.Fatal("multiple links accepted")
	}
	f.Close()
	if e := os.Remove(link); e != nil {
		t.Fatal(e)
	}
	d, e := openNativePath(dir, true)
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	if _, e = nativeIdentity(d, false); e == nil {
		t.Fatal("directory accepted as file")
	}
	child, e := openNativeChild(d, "record.bin", false)
	if e != nil {
		t.Fatal(e)
	}
	if e := fileObjectSecurity(windows.Handle(child.Fd()), true); e == nil {
		child.Close()
		t.Fatal("user-owned fixture trusted")
	}
	child.Close()
	for _, name := range []string{"Bimeron Core", "NativeEnrollment", "absent-record.bin"} {
		f, e := openNativeChild(d, name, name != "absent-record.bin")
		if e == nil {
			f.Close()
			t.Fatal("missing fixture unexpectedly present")
		}
		if !errors.Is(e, windows.ERROR_FILE_NOT_FOUND) {
			t.Fatalf("exact child not-found: %v", e)
		}
	}
	for _, tc := range []struct {
		index int
		err   error
		want  bool
	}{
		{0, windows.ERROR_FILE_NOT_FOUND, true}, {1, windows.ERROR_FILE_NOT_FOUND, true}, {2, windows.ERROR_FILE_NOT_FOUND, false},
		{0, windows.ERROR_PATH_NOT_FOUND, false}, {0, windows.ERROR_ACCESS_DENIED, false}, {1, windows.ERROR_SHARING_VIOLATION, false},
	} {
		if bootstrapMissing(tc.index, tc.err) != tc.want {
			t.Fatal(tc)
		}
	}
	// No protected native positive is attempted: user-owned fixtures establish rejection only.
}

func TestNativeReparseRejection(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if e := os.Mkdir(target, 0700); e != nil {
		t.Fatal(e)
	}
	link := filepath.Join(dir, "link")
	if e := os.Symlink(target, link); e != nil {
		t.Skipf("disposable symlink unavailable without privileges: %v", e)
	}
	f, e := openNativePath(link, true)
	if e != nil {
		return
	} // The native open may itself refuse the reparse.
	defer f.Close()
	if _, e := nativeIdentity(f, true); e == nil {
		t.Fatal("reparse accepted")
	}
	parent, e := openNativePath(dir, true)
	if e != nil {
		t.Fatal(e)
	}
	defer parent.Close()
	child, e := openNativeChild(parent, "link", true)
	if e == nil {
		defer child.Close()
		if _, e = nativeIdentity(child, true); e == nil {
			t.Fatal("relative reparse accepted")
		}
	}
}
