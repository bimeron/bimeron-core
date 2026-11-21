//go:build windows

package core

import (
	"bimeron/internal/killswitch"
	"errors"
	"io"
	"unsafe"

	"golang.org/x/sys/windows"
)

// holdFileSDDL limits the record to SYSTEM and administrators, also inside a
// directory that standard users may read.
const holdFileSDDL = "O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)"

func writeHoldFile(path string, b []byte) error {
	sd, err := windows.SecurityDescriptorFromString(holdFileSDDL)
	if err != nil {
		return err
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	// Discard the directory entry without opening an existing file with its old DACL.
	if err := windows.DeleteFile(name); err != nil && !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return err
	}
	h, err := windows.CreateFile(name, windows.GENERIC_WRITE, 0, &sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return err
	}

	var written uint32
	if err := windows.WriteFile(h, b, &written, nil); err != nil {
		windows.CloseHandle(h)
		return err
	}
	if int(written) != len(b) {
		windows.CloseHandle(h)
		return io.ErrShortWrite
	}
	return windows.CloseHandle(h)
}

func installedFilterGeneration() (string, error) { return killswitch.FilterGeneration() }

func (r *updateResume) matches() bool {
	record := r.hold.readRecord()
	return record.ProfileID == r.profile && record.Generation == r.generation
}
