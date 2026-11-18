// Package safefile reads profile-referenced files: local data files only,
// checked before and after opening, with a size limit.
package safefile

import (
	"errors"
	"io"
	"os"
)

var (
	// ErrNotLocal reports a file outside the local file system, such as a
	// Windows UNC, device-namespace or reserved device name path, or a file
	// that the opened handle shows to be on a network share.
	ErrNotLocal = errors.New("file path is not local")
	// ErrNotRegular reports a directory, device, pipe, socket or other file
	// that does not hold ordinary data.
	ErrNotRegular = errors.New("not a data file")
	// ErrTooLarge reports a file larger than the limit.
	ErrTooLarge = errors.New("file exceeds size limit")
)

// Read returns the contents of the data file at path if it has at most limit
// bytes. The path is checked with Stat before it is opened, so devices, FIFOs
// and named pipes are never opened; the opened file must be the same file and
// pass the same check. A data file is a regular file; on Windows it may also
// carry a reparse point that is not a link, such as a OneDrive cloud file, and
// the opened handle must be a local disk file. Other errors come from the file
// system and name the path.
func Read(path string, limit int64) ([]byte, error) {
	if !local(path) {
		return nil, ErrNotLocal
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !regular(info.Mode()) {
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
	if !regular(opened.Mode()) || !os.SameFile(info, opened) {
		return nil, ErrNotRegular
	}
	if err := checkOpened(f); err != nil {
		return nil, err
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
