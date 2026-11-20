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
	volumeNameDOS           = 0x0
)

// Reparse tags of special files that are not name surrogates: AF_UNIX
// sockets and the FIFOs and character and block devices that WSL creates.
const (
	reparseTagAFUnix = 0x80000023
	reparseTagLXFIFO = 0x80000024
	reparseTagLXChr  = 0x80000025
	reparseTagLXBlk  = 0x80000026
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
// directory, link, socket or WSL special file and is not on a remote file
// system.
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
	var attributes, tag uint32
	if fileType == windows.FILE_TYPE_DISK {
		var op string
		if attributes, tag, op, err = attributeTag(h); err != nil {
			return &os.PathError{Op: op, Path: name, Err: err}
		}
	}
	if err := checkKind(fileType, attributes, tag); err != nil {
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

// Handle queries, replaced in tests.
var (
	getFileInformation = windows.GetFileInformationByHandle
	getAttributeTag    = func(h windows.Handle, info *fileAttributeTagInfo) error {
		return windows.GetFileInformationByHandleEx(h, windows.FileAttributeTagInfo, (*byte)(unsafe.Pointer(info)), uint32(unsafe.Sizeof(*info)))
	}
)

// attributeTag returns the file attributes and, for a reparse point, its tag.
// FileAttributeTagInfo is queried only for reparse points, as os.Stat does,
// because some file system drivers do not implement it. op names the query
// that failed.
func attributeTag(h windows.Handle) (attributes, tag uint32, op string, err error) {
	var file windows.ByHandleFileInformation
	if err = getFileInformation(h, &file); err != nil {
		return 0, 0, "GetFileInformationByHandle", err
	}
	if file.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0 {
		return file.FileAttributes, 0, "", nil
	}
	var info fileAttributeTagInfo
	if err = getAttributeTag(h, &info); err != nil {
		return 0, 0, "GetFileInformationByHandleEx", err
	}
	return info.FileAttributes, info.ReparseTag, "", nil
}

// checkKind decides from the handle's file type, attributes and reparse tag.
// Name surrogates are already resolved when the file is opened, so one on the
// opened handle is rejected, as are sockets and WSL special files.
func checkKind(fileType, attributes, tag uint32) error {
	if fileType != windows.FILE_TYPE_DISK || attributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
		return ErrNotRegular
	}
	if attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 && (tag&reparseTagNameSurrogate != 0 || specialFileTag(tag)) {
		return ErrNotRegular
	}
	return nil
}

func specialFileTag(tag uint32) bool {
	switch tag {
	case reparseTagAFUnix, reparseTagLXFIFO, reparseTagLXChr, reparseTagLXBlk:
		return true
	}
	return false
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
