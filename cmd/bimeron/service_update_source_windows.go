//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// stagedUpdateSDDL keeps a staged update private until it is verified.
const stagedUpdateSDDL = "D:P(A;;FA;;;SY)(A;;FA;;;BA)"

// openUpdateSource opens the named file itself, never a link target, and
// accepts only a regular file on a local fixed drive.
func openUpdateSource(source string) (*os.File, error) {
	volume := filepath.VolumeName(source)
	if len(volume) != 2 || volume[1] != ':' || !filepath.IsAbs(source) {
		return nil, fmt.Errorf("update source must be on a local drive")
	}
	root, err := windows.UTF16PtrFromString(volume + `\`)
	if err != nil {
		return nil, err
	}
	if windows.GetDriveType(root) != windows.DRIVE_FIXED {
		return nil, fmt.Errorf("update source must be on a local drive")
	}
	name, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: source, Err: err}
	}
	var info windows.ByHandleFileInformation
	kind, typeErr := windows.GetFileType(h)
	if err = windows.GetFileInformationByHandle(h, &info); err != nil || typeErr != nil || kind != windows.FILE_TYPE_DISK ||
		info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		windows.CloseHandle(h)
		return nil, errUpdateSourceNotRegular
	}
	return os.NewFile(uintptr(h), source), nil
}

// createPrivateUpdateFile creates a new file readable only by SYSTEM and
// Administrators and shares nothing while it is written.
func createPrivateUpdateFile(path string) (*os.File, error) {
	sd, err := windows.SecurityDescriptorFromString(stagedUpdateSDDL)
	if err != nil {
		return nil, err
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(name, windows.GENERIC_WRITE, 0, &sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, &os.PathError{Op: "create", Path: path, Err: err}
	}
	return os.NewFile(uintptr(h), path), nil
}

// copyUpdateSource stages the untrusted update source privately.
func copyUpdateSource(source, staged string) error {
	in, err := openUpdateSource(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := createPrivateUpdateFile(staged)
	if err != nil {
		return err
	}
	return copyUpdateData(out, in)
}

// inheritServiceFileACL replaces the private staging DACL with the one the
// protected service directory gives installed files.
func inheritServiceFileACL(path string) error {
	sd, err := windows.SecurityDescriptorFromString("D:")
	if err != nil {
		return err
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.UNPROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}
