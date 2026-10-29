//go:build windows

package control

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var errForegroundIdentity = errors.New("foreground_identity_rejected")

func trustedFileOwner(sid string) bool {
	return sid == "S-1-5-18" || sid == "S-1-5-32-544" || sid == "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
}

// Fail closed on unfamiliar ACEs rather than guessing effective write access.
func protectedObject(h windows.Handle) error {
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return errForegroundIdentity
	}
	return protectedDescriptor(sd)
}

func protectedDescriptor(sd *windows.SECURITY_DESCRIPTOR) error {
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !trustedFileOwner(owner.String()) {
		return errForegroundIdentity
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		return errForegroundIdentity
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, i, &ace) != nil {
			return errForegroundIdentity
		}
		if ace.Header.AceFlags&0x8 != 0 {
			continue
		} // inherit-only
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return errForegroundIdentity
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		// Data/append, attributes/EA, delete-child, delete, WRITE_DAC/OWNER and generic writes.
		if uint32(ace.Mask)&0x500d0156 != 0 && !trustedFileOwner(sid.String()) {
			return errForegroundIdentity
		}
	}
	return nil
}

func openLocked(path string, directory bool) (*os.File, error) {
	ptr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, errForegroundIdentity
	}
	flags := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if directory {
		flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
	}
	h, err := windows.CreateFile(ptr, windows.GENERIC_READ|windows.READ_CONTROL, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, flags, 0)
	if err != nil {
		return nil, errForegroundIdentity
	}
	var info windows.ByHandleFileInformation
	kind, kindErr := windows.GetFileType(h)
	if kindErr != nil || kind != windows.FILE_TYPE_DISK || windows.GetFileInformationByHandle(h, &info) != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		windows.CloseHandle(h)
		return nil, errForegroundIdentity
	}
	return os.NewFile(uintptr(h), path), nil
}

// Pin ancestors before opening the config, so a junction cannot redirect an
// elevated read to a remote share/device or change reference meaning.
func lockForegroundConfig(path string) (*os.File, func(), error) {
	if len(path) < 3 || path[1] != ':' || (path[2] != '\\' && path[2] != '/') || strings.Contains(path[2:], ":") {
		return nil, nil, errForegroundIdentity
	}
	clean := filepath.Clean(path)
	root := filepath.VolumeName(clean) + string(os.PathSeparator)
	ptr, err := windows.UTF16PtrFromString(root)
	if err != nil || windows.GetDriveType(ptr) != windows.DRIVE_FIXED {
		return nil, nil, errForegroundIdentity
	}
	files := []*os.File{}
	release := func() {
		for i := len(files) - 1; i >= 0; i-- {
			files[i].Close()
		}
	}
	directories := []string{}
	for p := filepath.Dir(clean); ; p = filepath.Dir(p) {
		directories = append(directories, p)
		if strings.EqualFold(p, root) {
			break
		}
	}
	for i := len(directories) - 1; i >= 0; i-- {
		f, e := openLocked(directories[i], true)
		if e != nil {
			release()
			return nil, nil, e
		}
		files = append(files, f)
	}
	f, err := openLocked(clean, false)
	if err != nil {
		release()
		return nil, nil, err
	}
	files = append(files, f)
	return f, release, nil
}

// lockImage pins the image and all directories below Program Files against
// replacement. Caller keeps every returned handle until peer use completes.
func lockImage(path string) ([]*os.File, string, error) { return lockExpectedImage(path, nil) }

func lockExpectedImage(path string, expected *ProcessIdentity) ([]*os.File, string, error) {
	root, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if err != nil {
		return nil, "", errForegroundIdentity
	}
	clean := filepath.Clean(path)
	relative, err := filepath.Rel(root, clean)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		return nil, "", errForegroundIdentity
	}
	files := []*os.File{}
	fail := func() ([]*os.File, string, error) {
		for _, f := range files {
			f.Close()
		}
		return nil, "", errForegroundIdentity
	}
	paths := []string{}
	for p := clean; ; p = filepath.Dir(p) {
		paths = append(paths, p)
		if strings.EqualFold(p, root) {
			break
		}
	}
	for i := len(paths) - 1; i >= 0; i-- {
		p := paths[i]
		f, e := openLocked(p, p != clean)
		if e != nil {
			return fail()
		}
		files = append(files, f)
		if protectedObject(windows.Handle(f.Fd())) != nil {
			return fail()
		}
	}
	// Keep the image at index zero for hashing/file identity; directories remain pinned.
	files = append([]*os.File{files[len(files)-1]}, files[:len(files)-1]...)

	if expected != nil {
		var info windows.ByHandleFileInformation
		if windows.GetFileInformationByHandle(windows.Handle(files[0].Fd()), &info) == nil && info.VolumeSerialNumber == expected.ImageVolume && (uint64(info.FileIndexHigh)<<32|uint64(info.FileIndexLow)) == expected.ImageIndex {
			return files, expected.ImageSHA256, nil
		}
		return fail()
	}
	digest := sha256.New()
	if _, err = io.Copy(digest, files[0]); err != nil {
		return fail()
	}
	return files, hex.EncodeToString(digest.Sum(nil)), nil
}

func inspectProcess(pid uint32) (ProcessIdentity, func(), error) {
	return inspectExpectedProcess(pid, nil)
}

func inspectExpectedProcess(pid uint32, expected *ProcessIdentity) (ProcessIdentity, func(), error) {
	result := ProcessIdentity{PID: pid}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, pid)
	if err != nil {
		return result, nil, errForegroundIdentity
	}
	closeProcess := func() { windows.CloseHandle(h) }
	var created, exit, kernel, user windows.Filetime
	var token windows.Token
	if windows.GetProcessTimes(h, &created, &exit, &kernel, &user) != nil || windows.OpenProcessToken(h, windows.TOKEN_QUERY, &token) != nil {
		closeProcess()
		return result, nil, errForegroundIdentity
	}
	defer token.Close()
	u, err := token.GetTokenUser()
	if err != nil {
		closeProcess()
		return result, nil, errForegroundIdentity
	}
	result.SID = u.User.Sid.String()
	result.Created = uint64(created.HighDateTime)<<32 | uint64(created.LowDateTime)
	result.Elevated = token.IsElevated()
	var returned uint32
	if windows.GetTokenInformation(token, windows.TokenSessionId, (*byte)(unsafe.Pointer(&result.Session)), 4, &returned) != nil || result.Session == 0 {
		closeProcess()
		return result, nil, errForegroundIdentity
	}
	path := make([]uint16, 32768)
	size := uint32(len(path))
	if windows.QueryFullProcessImageName(h, 0, &path[0], &size) != nil {
		closeProcess()
		return result, nil, errForegroundIdentity
	}
	files, digest, err := lockExpectedImage(windows.UTF16ToString(path[:size]), expected)
	if err != nil {
		closeProcess()
		return result, nil, errForegroundIdentity
	}
	result.ImageSHA256 = digest
	var imageInfo windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(windows.Handle(files[0].Fd()), &imageInfo) != nil {
		for _, f := range files {
			f.Close()
		}
		closeProcess()
		return result, nil, errForegroundIdentity
	}
	result.ImageVolume = imageInfo.VolumeSerialNumber
	result.ImageIndex = uint64(imageInfo.FileIndexHigh)<<32 | uint64(imageInfo.FileIndexLow)
	cleanup := func() {
		for _, f := range files {
			f.Close()
		}
		closeProcess()
	}
	state, err := windows.WaitForSingleObject(h, 0)
	if err != nil || state != uint32(windows.WAIT_TIMEOUT) {
		cleanup()
		return result, nil, errForegroundIdentity
	}
	return result, cleanup, nil
}

func foregroundPipe(sid string, session uint32) string {
	sum := sha256.Sum256([]byte(sid))
	return fmt.Sprintf(`\\.\pipe\Bimeron.Core.IKEv2.%x.%d`, sum[:16], session)
}

func pipePeer(c net.Conn, server bool) (ProcessIdentity, func(), error) {
	return expectedPipePeer(c, server, nil)
}

func expectedPipePeer(c net.Conn, server bool, expected *ProcessIdentity) (ProcessIdentity, func(), error) {
	fd, ok := c.(interface{ Fd() uintptr })
	if !ok {
		return ProcessIdentity{}, nil, errForegroundIdentity
	}
	var pid uint32
	var err error
	if server {
		err = windows.GetNamedPipeClientProcessId(windows.Handle(fd.Fd()), &pid)
	} else {
		err = windows.GetNamedPipeServerProcessId(windows.Handle(fd.Fd()), &pid)
	}
	if err != nil {
		return ProcessIdentity{}, nil, errForegroundIdentity
	}
	return inspectExpectedProcess(pid, expected)
}
