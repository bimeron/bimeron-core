//go:build windows

package nativeenrollment

import (
	"errors"
	"io"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ReadNativeFile observes only the fixed Core location. It neither publishes
// state nor grants admission. Enrollment remains disabled. Matching snapshots
// cannot establish atomic admission, detect ABA, or detect privileged deletion.
func ReadNativeFile(expected *Binding) Observation {
	folder, e := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if e != nil {
		return Observation{Result: UnsafeRead, Expected: expected}
	}
	return readNativeFolder(folder, expected)
}

// The private path seam permits disposable rejection fixtures only; all native
// identity, ancestry and descriptor checks still run without overrides.
func readNativeFolder(folder string, expected *Binding) (result Observation) {
	result = Observation{Result: UnsafeRead, Expected: expected}
	// A WOW64 ProgramFiles result may identify Program Files (x86). Refuse it
	// rather than label a redirected known-folder object as the native location.
	var processMachine, nativeMachine uint16
	if windows.IsWow64Process2(windows.CurrentProcess(), &processMachine, &nativeMachine) != nil {
		return
	}
	if processMachine != 0 {
		nativeFolder, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFilesX64, 0)
		if err != nil {
			return
		}
		a, err := openNativePath(folder, true)
		if err != nil {
			return
		}
		b, err := openNativePath(nativeFolder, true)
		if err != nil {
			a.Close()
			return
		}
		ai, ae := nativeIdentity(a, true)
		bi, be := nativeIdentity(b, true)
		ac, bc := a.Close(), b.Close()
		if ae != nil || be != nil || ac != nil || bc != nil || ai != bi {
			return
		}
	}
	drive, parts, e := nativeFolderParts(folder)
	if e != nil {
		return
	}
	mount, _ := windows.UTF16PtrFromString(drive)
	if windows.GetDriveType(mount) != windows.DRIVE_FIXED {
		return
	}
	volume := make([]uint16, 64)
	if windows.GetVolumeNameForVolumeMountPoint(mount, &volume[0], uint32(len(volume))) != nil {
		return
	}
	root := windows.UTF16ToString(volume)
	if !nativeVolumeRoot(root) {
		return
	}
	rootPtr, _ := windows.UTF16PtrFromString(root)
	if windows.GetDriveType(rootPtr) != windows.DRIVE_FIXED {
		return
	}
	files := []*os.File{}
	defer func() {
		if closeNativeFiles(files) != nil {
			result = Observation{Result: UnsafeRead, Expected: expected}
		}
	}()
	f, e := openNativePath(root, true)
	if e != nil {
		return
	}
	files = append(files, f)
	rootID, e := nativeIdentity(f, true)
	if e != nil || fileObjectSecurity(windows.Handle(f.Fd()), false) != nil {
		return
	}
	final, e := nativeFinalPath(f)
	if e != nil || !strings.EqualFold(strings.TrimSuffix(final, `\`), strings.TrimSuffix(root, `\`)) {
		return
	}
	ids := []nativeFileID{rootID}
	names := append(append([]string{}, parts...), "Bimeron Core", "NativeEnrollment", "record.bin")
	missing := -1
	for i, name := range names {
		directory := i < len(names)-1
		child, err := openNativeChild(files[len(files)-1], name, directory)
		if err != nil {
			// Only exact missing child at a fixed bootstrap directory qualifies;
			// the nearest held ancestor has already passed all security checks.
			if i >= len(parts) && bootstrapMissing(i-len(parts), err) {
				missing = i
				break
			}
			return
		}
		files = append(files, child)
		id, err := nativeIdentity(child, directory)
		if err != nil || id.Volume != rootID.Volume || fileObjectSecurity(windows.Handle(child.Fd()), i >= len(parts)+1) != nil {
			return
		}
		ids = append(ids, id)
	}
	// Independently open the known-folder spelling and compare its identity with
	// the GUID-root traversal. The drive spelling alone is never a root pin.
	known, e := openNativePath(folder, true)
	if e != nil {
		return
	}
	knownID, e := nativeIdentity(known, true)
	closeErr := known.Close()
	if e != nil || closeErr != nil || knownID != ids[len(parts)] {
		return
	}
	recheck := func() error {
		for i, f := range files {
			directory := missing >= 0 || i < len(files)-1
			id, err := nativeIdentity(f, directory)
			if err != nil || id != ids[i] || fileObjectSecurity(windows.Handle(f.Fd()), i >= len(parts)+2) != nil {
				return errNativeFile
			}
			if i > 0 {
				again, err := openNativeChild(files[i-1], names[i-1], directory)
				if err != nil {
					return errNativeFile
				}
				actual, err := nativeIdentity(again, directory)
				ce := again.Close()
				if err != nil || ce != nil || actual != ids[i] {
					return errNativeFile
				}
			}
		}
		// A change to the known-folder mapping or drive resolution also denies.
		current, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
		if err != nil {
			return errNativeFile
		}
		again, err := openNativePath(current, true)
		if err != nil {
			return errNativeFile
		}
		id, err := nativeIdentity(again, true)
		ce := again.Close()
		if err != nil || ce != nil || id != knownID {
			return errNativeFile
		}
		if processMachine != 0 {
			path, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFilesX64, 0)
			if err != nil {
				return errNativeFile
			}
			native, err := openNativePath(path, true)
			if err != nil {
				return errNativeFile
			}
			id, err := nativeIdentity(native, true)
			ce := native.Close()
			if err != nil || ce != nil || id != knownID {
				return errNativeFile
			}
		}
		return nil
	}
	if recheck() != nil {
		return
	}
	if missing >= 0 {
		// Re-probe under the same held, validated parent. PATH_NOT_FOUND and
		// disappearance elsewhere never become bootstrap absence.
		again, err := openNativeChild(files[len(files)-1], names[missing], true)
		if err == nil {
			again.Close()
			return
		}
		if !bootstrapMissing(missing-len(parts), err) || recheck() != nil {
			return
		}
		result.Result = ProtectedAbsence
		result.First = Snapshot{View: NativeView, Security: Protected}
		result.Second = result.First
		return
	}
	first, e := recordSample(files[len(files)-1])
	if e != nil || recheck() != nil {
		return
	}
	second, e := recordSample(files[len(files)-1])
	if e != nil || recheck() != nil {
		return
	}
	result.Result = Present
	result.First = Snapshot{View: NativeView, Security: Protected, Bytes: first}
	result.Second = Snapshot{View: NativeView, Security: Protected, Bytes: second}
	return
}

func nativeComponent(s string) bool {
	return s != "" && s != "." && s != ".." && !strings.ContainsAny(s, `\/:*?"<>|`+"\x00") && !strings.HasSuffix(s, ".") && !strings.HasSuffix(s, " ")
}
func nativeFolderParts(path string) (string, []string, error) {
	if len(path) < 4 || !((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) || path[1:3] != `:\` {
		return "", nil, errNativeFile
	}
	parts := strings.Split(path[3:], `\`)
	for _, p := range parts {
		if !nativeComponent(p) {
			return "", nil, errNativeFile
		}
	}
	return path[:3], parts, nil
}
func nativeVolumeRoot(s string) bool {
	if len(s) != 49 || !strings.HasPrefix(s, `\\?\Volume{`) || !strings.HasSuffix(s, `}\`) {
		return false
	}
	_, e := windows.GUIDFromString(s[10:48])
	return e == nil
}
func openNativePath(path string, directory bool) (*os.File, error) {
	p, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return nil, errNativeFile
	}
	flags := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if directory {
		flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
	}
	h, e := windows.CreateFile(p, windows.FILE_GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, flags, 0)
	if e != nil {
		return nil, e
	}
	return os.NewFile(uintptr(h), path), nil
}

// Relative, one-component opens bind each child to its already held parent.
func openNativeChild(parent *os.File, name string, directory bool) (*os.File, error) {
	if !nativeComponent(name) {
		return nil, errNativeFile
	}
	n, e := windows.NewNTUnicodeString(name)
	if e != nil {
		return nil, e
	}
	oa := windows.OBJECT_ATTRIBUTES{RootDirectory: windows.Handle(parent.Fd()), ObjectName: n, Attributes: windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE}
	oa.Length = uint32(unsafe.Sizeof(oa))
	options := uint32(windows.FILE_OPEN_REPARSE_POINT | windows.FILE_SYNCHRONOUS_IO_NONALERT)
	if directory {
		options |= windows.FILE_DIRECTORY_FILE
	} else {
		options |= windows.FILE_NON_DIRECTORY_FILE
	}
	var h windows.Handle
	var status windows.IO_STATUS_BLOCK
	e = windows.NtCreateFile(&h, windows.FILE_GENERIC_READ, &oa, &status, nil, 0, windows.FILE_SHARE_READ, windows.FILE_OPEN, options, 0, 0)
	if e != nil {
		var nt windows.NTStatus
		if errors.As(e, &nt) {
			return nil, nt.Errno()
		}
		return nil, e
	}
	return os.NewFile(uintptr(h), name), nil
}

type nativeFileID struct {
	Volume uint64
	Index  [16]byte
	Links  uint32
}

func nativeIdentity(f *os.File, directory bool) (nativeFileID, error) {
	h := windows.Handle(f.Fd())
	var info windows.ByHandleFileInformation
	kind, e := windows.GetFileType(h)
	if e != nil || kind != windows.FILE_TYPE_DISK || windows.GetFileInformationByHandle(h, &info) != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || (info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != directory || (!directory && info.NumberOfLinks != 1) {
		return nativeFileID{}, errNativeFile
	}
	if directory {
		var flags uint32
		if windows.GetFileInformationByHandleEx(h, windows.FileCaseSensitiveInfo, (*byte)(unsafe.Pointer(&flags)), 4) != nil || flags != 0 {
			return nativeFileID{}, errNativeFile
		}
	}
	var id struct {
		Volume uint64
		Index  [16]byte
	}
	if windows.GetFileInformationByHandleEx(h, windows.FileIdInfo, (*byte)(unsafe.Pointer(&id)), uint32(unsafe.Sizeof(id))) != nil || id.Volume == 0 || id.Index == [16]byte{} {
		return nativeFileID{}, errNativeFile
	}
	return nativeFileID{id.Volume, id.Index, info.NumberOfLinks}, nil
}
func nativeFinalPath(f *os.File) (string, error) {
	b := make([]uint16, 32768)
	n, e := windows.GetFinalPathNameByHandle(windows.Handle(f.Fd()), &b[0], uint32(len(b)), 1) // VOLUME_NAME_GUID
	if e != nil || n == 0 || n >= uint32(len(b)) {
		return "", errNativeFile
	}
	return windows.UTF16ToString(b[:n]), nil
}
func bootstrapMissing(index int, e error) bool {
	return (index == 0 || index == 1) && errors.Is(e, windows.ERROR_FILE_NOT_FOUND)
}
func recordSample(r io.ReaderAt) ([]byte, error) {
	b := make([]byte, 65)
	n, e := r.ReadAt(b, 0)
	if e != nil && e != io.EOF {
		return nil, e
	}
	return b[:n], nil
}
func closeNativeFiles(files []*os.File) error {
	var result error
	for i := len(files) - 1; i >= 0; i-- {
		result = errors.Join(result, files[i].Close())
	}
	return result
}
