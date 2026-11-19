//go:build windows

package core

import (
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
	h, err := windows.CreateFile(name, windows.GENERIC_WRITE, 0, &sa, windows.CREATE_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	var written uint32
	if err := windows.WriteFile(h, b, &written, nil); err != nil {
		return err
	}
	return nil
}
