//go:build windows

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// stagedUpdateSDDL keeps a staged update private until it is verified.
const stagedUpdateSDDL = "D:P(A;;FA;;;SY)(A;;FA;;;BA)"

// reparseTagNameSurrogate marks reparse points that redirect to another
// name: symbolic links, junctions and similar tags.
const reparseTagNameSurrogate = 0x20000000

// Reparse tags of special files that are not name surrogates: AF_UNIX
// sockets and the FIFOs and character and block devices that WSL creates.
const (
	reparseTagAFUnix = 0x80000023
	reparseTagLXFIFO = 0x80000024
	reparseTagLXChr  = 0x80000025
	reparseTagLXBlk  = 0x80000026
)

// GetFinalPathNameByHandle flags.
const (
	fileNameNormalized = 0x0
	volumeNameDOS      = 0x0
	volumeNameGUID     = 0x1
)

var errUpdateSourceNotLocal = errors.New("update source must be on a fixed local drive")

// openUpdateSource opens the named file itself, never a link target, and
// accepts only a regular file on a fixed local drive. The path text is checked
// first; the opened handle is then checked again because directories in the
// path may still redirect elsewhere.
func openUpdateSource(source string) (*os.File, error) {
	if !fixedDrivePath(source) {
		return nil, errUpdateSourceNotLocal
	}
	name, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		// Without FILE_FLAG_BACKUP_SEMANTICS a directory fails to open with
		// access denied; report it as what it is. A junction or directory
		// symbolic link is a directory too, but is reported as a link.
		if attrs, attrErr := windows.GetFileAttributes(name); attrErr == nil && attrs&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
			if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 && directoryNameSurrogate(name) {
				return nil, errUpdateSourceLink
			}
			return nil, errUpdateSourceNotRegular
		}
		return nil, &os.PathError{Op: "open", Path: source, Err: err}
	}
	if err = checkUpdateSourceHandle(h); err != nil {
		windows.CloseHandle(h)
		return nil, err
	}
	return os.NewFile(uintptr(h), source), nil
}

// directoryNameSurrogate reports whether the directory reparse point at name
// is a name surrogate, such as a junction or a directory symbolic link. It
// opens the reparse point itself for attributes only.
func directoryNameSurrogate(name *uint16) bool {
	h, err := windows.CreateFile(name, windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	var tag struct{ FileAttributes, ReparseTag uint32 } // FILE_ATTRIBUTE_TAG_INFO
	if windows.GetFileInformationByHandleEx(h, windows.FileAttributeTagInfo, (*byte)(unsafe.Pointer(&tag)), uint32(unsafe.Sizeof(tag))) != nil {
		return false
	}
	return tag.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 && tag.ReparseTag&reparseTagNameSurrogate != 0
}

// fixedDrivePath accepts only an absolute drive-letter path whose drive is
// DRIVE_FIXED; UNC, device and extended-length (\\?\) paths are refused.
func fixedDrivePath(path string) bool {
	volume := filepath.VolumeName(path)
	if len(volume) != 2 || volume[1] != ':' || !filepath.IsAbs(path) {
		return false
	}
	root, err := windows.UTF16PtrFromString(volume + `\`)
	return err == nil && windows.GetDriveType(root) == windows.DRIVE_FIXED
}

// checkUpdateSourceHandle accepts a disk file that is neither a directory, a
// name-surrogate reparse point nor a socket or WSL special file and that
// resolves to a fixed local volume. Other reparse points, such as cloud-file
// placeholders or deduplicated files, are read as ordinary data; the staged
// digest check covers their content.
func checkUpdateSourceHandle(h windows.Handle) error {
	if kind, err := windows.GetFileType(h); err != nil || kind != windows.FILE_TYPE_DISK {
		return errUpdateSourceNotRegular
	}
	var tag struct{ FileAttributes, ReparseTag uint32 } // FILE_ATTRIBUTE_TAG_INFO
	if err := windows.GetFileInformationByHandleEx(h, windows.FileAttributeTagInfo, (*byte)(unsafe.Pointer(&tag)), uint32(unsafe.Sizeof(tag))); err != nil {
		return err
	}
	if tag.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 && tag.ReparseTag&reparseTagNameSurrogate != 0 {
		return errUpdateSourceLink
	}
	if tag.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 || tag.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 && specialFileTag(tag.ReparseTag) {
		return errUpdateSourceNotRegular
	}
	return checkUpdateSourceLocal(h)
}

func specialFileTag(tag uint32) bool {
	switch tag {
	case reparseTagAFUnix, reparseTagLXFIFO, reparseTagLXChr, reparseTagLXBlk:
		return true
	}
	return false
}

// checkUpdateSourceLocal rejects a handle served by a network redirector,
// whose final path is not on a fixed drive letter, or whose volume is not a
// fixed drive.
func checkUpdateSourceLocal(h windows.Handle) error {
	if remoteProtocolInfo(h) == nil {
		return errUpdateSourceNotLocal
	}
	final, err := finalPathName(h, fileNameNormalized|volumeNameDOS)
	if err != nil || !fixedDriveFinalPath(final) || !fixedVolume(h) {
		return errUpdateSourceNotLocal
	}
	return nil
}

// finalPathName returns the final path of the opened file in the form that
// flags select.
func finalPathName(h windows.Handle, flags uint32) (string, error) {
	buf := make([]uint16, windows.MAX_PATH)
	for {
		n, err := windows.GetFinalPathNameByHandle(h, &buf[0], uint32(len(buf)), flags)
		if err != nil {
			return "", err
		}
		if n < uint32(len(buf)) {
			return windows.UTF16ToString(buf[:n]), nil
		}
		buf = make([]uint16, n)
	}
}

// fixedVolume reports whether the volume that holds the opened file is
// DRIVE_FIXED. The drive letter alone does not tell: a removable or other
// volume can be mounted in a folder of a fixed drive. The volume comes from
// the handle (its volume GUID path), not from the path text, so a folder
// replaced after opening cannot redirect the check. A volume without a GUID
// path is refused.
func fixedVolume(h windows.Handle) bool {
	final, err := finalPathName(h, fileNameNormalized|volumeNameGUID)
	if err != nil {
		return false
	}
	root, ok := volumeGUIDRoot(final)
	if !ok {
		return false
	}
	name, err := windows.UTF16PtrFromString(root)
	return err == nil && windows.GetDriveType(name) == windows.DRIVE_FIXED
}

// volumeGUIDRoot returns the \\?\Volume{GUID}\ root of a VOLUME_NAME_GUID
// final path.
func volumeGUIDRoot(final string) (string, bool) {
	const prefix = `\\?\Volume{`
	if len(final) < len(prefix) || !strings.EqualFold(final[:len(prefix)], prefix) {
		return "", false
	}
	end := strings.IndexByte(final[len(prefix):], '}')
	if end < 0 {
		return "", false
	}
	root := final[:len(prefix)+end+1]
	if rest := final[len(root):]; rest != "" && rest[0] != '\\' {
		return "", false
	}
	return root + `\`, true
}

// remoteProtocolInfo queries FILE_REMOTE_PROTOCOL_INFO, which only network
// redirectors provide; local file systems fail the query.
func remoteProtocolInfo(h windows.Handle) error {
	var info [15]uint64 // 116-byte FILE_REMOTE_PROTOCOL_INFO, 8-byte aligned
	return windows.GetFileInformationByHandleEx(h, windows.FileRemoteProtocolInfo, (*byte)(unsafe.Pointer(&info[0])), 116)
}

// fixedDriveFinalPath accepts a VOLUME_NAME_DOS final path of the form
// \\?\X:\... whose drive is DRIVE_FIXED; \\?\UNC\ and any other form are
// refused. The volume that holds the file is checked separately.
func fixedDriveFinalPath(final string) bool {
	const prefix = `\\?\`
	if len(final) < len(prefix)+3 || final[:len(prefix)] != prefix {
		return false
	}
	drive := final[len(prefix):]
	letter := drive[0] | 0x20
	if letter < 'a' || letter > 'z' || drive[1] != ':' || drive[2] != '\\' {
		return false
	}
	return fixedDrivePath(drive)
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
	// A staged file left by an interrupted update would block CREATE_NEW. The
	// staging name is fixed inside the protected service directory, so
	// removing it only discards our own unverified copy.
	if err = os.Remove(staged); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove stale staged update: %w", err)
	}
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
