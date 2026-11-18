package safefile

import (
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	// reparseTagNameSurrogate marks reparse points that name another file,
	// such as symbolic links and mount points.
	reparseTagNameSurrogate = 0x20000000
	reparseTagAFUnix        = 0x80000023
	volumeNameDOS           = 0x0
)

// regular accepts regular files and data files carrying a reparse point that
// is not a name surrogate, such as OneDrive cloud files. Go reports the latter
// as ModeIrregular. Directories, devices, pipes and sockets keep their type
// bits and are rejected.
func regular(m os.FileMode) bool {
	t := m.Type()
	return t == 0 || t == os.ModeIrregular
}

// checkOpened checks the opened handle: it must be a disk file that is not a
// directory, link or socket and is not on a remote file system.
func checkOpened(f *os.File) error {
	c, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var checkErr error
	if err := c.Control(func(fd uintptr) { checkErr = checkHandle(f.Name(), windows.Handle(fd)) }); err != nil {
		return err
	}
	return checkErr
}

func checkHandle(name string, h windows.Handle) error {
	fileType, err := windows.GetFileType(h)
	if err != nil {
		return &os.PathError{Op: "GetFileType", Path: name, Err: err}
	}
	var info fileAttributeTagInfo
	if fileType == windows.FILE_TYPE_DISK {
		if err := windows.GetFileInformationByHandleEx(h, windows.FileAttributeTagInfo, (*byte)(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
			return &os.PathError{Op: "GetFileInformationByHandleEx", Path: name, Err: err}
		}
	}
	if err := checkKind(fileType, info.FileAttributes, info.ReparseTag); err != nil {
		return err
	}
	if remote(h) {
		return ErrNotLocal
	}
	return nil
}

type fileAttributeTagInfo struct {
	FileAttributes uint32
	ReparseTag     uint32
}

// checkKind decides from the handle's file type, attributes and reparse tag.
// Name surrogates are already resolved when the file is opened, so one on the
// opened handle is rejected.
func checkKind(fileType, attributes, tag uint32) error {
	if fileType != windows.FILE_TYPE_DISK || attributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
		return ErrNotRegular
	}
	if attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 && (tag&reparseTagNameSurrogate != 0 || tag == reparseTagAFUnix) {
		return ErrNotRegular
	}
	return nil
}

// fileRemoteProtocolInfo is FILE_REMOTE_PROTOCOL_INFO.
type fileRemoteProtocolInfo struct {
	StructureVersion     uint16
	StructureSize        uint16
	Protocol             uint32
	ProtocolMajorVersion uint16
	ProtocolMinorVersion uint16
	ProtocolRevision     uint16
	Reserved             uint16
	Flags                uint32
	GenericReserved      [8]uint32
	ProtocolSpecific     [16]uint32
}

// remote reports a file on a network redirector, including one reached
// through a mapped drive, SUBST drive, symbolic link or mount point.
func remote(h windows.Handle) bool {
	var info fileRemoteProtocolInfo
	if windows.GetFileInformationByHandleEx(h, windows.FileRemoteProtocolInfo, (*byte)(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))) == nil {
		return true
	}
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetFinalPathNameByHandle(h, &buf[0], uint32(len(buf)), volumeNameDOS)
	return err == nil && int(n) < len(buf) && uncFinalPath(windows.UTF16ToString(buf[:n]))
}

func uncFinalPath(path string) bool {
	return len(path) >= 8 && strings.EqualFold(path[:8], `\\?\UNC\`)
}
