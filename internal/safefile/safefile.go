// Package safefile reads profile-referenced files: local regular files only,
// checked before opening, with a size limit.
package safefile

import (
	"errors"
	"io"
	"os"
)

var (
	// ErrNotLocal reports a path outside the local file system, such as a
	// Windows UNC, device-namespace or reserved device name path.
	ErrNotLocal = errors.New("file path is not local")
	// ErrNotRegular reports a directory, device, pipe, socket or other
	// non-regular file.
	ErrNotRegular = errors.New("not a regular file")
	// ErrTooLarge reports a file larger than the limit.
	ErrTooLarge = errors.New("file exceeds size limit")
)

// Read returns the contents of the regular file at path if it has at most
// limit bytes. The path is checked with Stat before it is opened, so devices,
// FIFOs and named pipes are never opened; the opened file must be the same
// regular file. Other errors come from the file system and name the path.
func Read(path string, limit int64) ([]byte, error) {
	if !local(path) {
		return nil, ErrNotLocal
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, ErrNotRegular
	}
	f, err := open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, ErrNotRegular
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, ErrTooLarge
	}
	return b, nil
}
