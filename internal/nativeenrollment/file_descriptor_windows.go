//go:build windows

package nativeenrollment

import (
	"encoding/binary"
	"errors"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

var errNativeFile = errors.New("unsafe native enrollment file evidence")

func trustedNativeSID(s string) bool {
	return s == "S-1-5-18" || s == "S-1-5-32-544" || s == "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
}

type fileSecurityPolicy uint8

const (
	ordinaryFilePolicy fileSecurityPolicy = iota
	volumeRootPolicy
)

func fileObjectSecurity(h windows.Handle, protected bool) error {
	return fileObjectSecurityPolicy(h, protected, ordinaryFilePolicy)
}

func fileObjectSecurityPolicy(h windows.Handle, protected bool, policy fileSecurityPolicy) error {
	sd, e := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if e != nil {
		return errNativeFile
	}
	return fileDescriptorPolicy(sd, protected, policy)
}

// fileDescriptor does not use deny entries to excuse an unsafe allow. Ancestors
// may inherit a safe DACL; the enrollment container and leaf must protect theirs.
// Inputs are OS-owned descriptors or valid allocated in-memory descriptors.
func fileDescriptor(sd *windows.SECURITY_DESCRIPTOR, protected bool) error {
	return fileDescriptorPolicy(sd, protected, ordinaryFilePolicy)
}

func fileDescriptorPolicy(sd *windows.SECURITY_DESCRIPTOR, protected bool, policy fileSecurityPolicy) error {
	if sd == nil || !sd.IsValid() {
		return errNativeFile
	}
	defer runtime.KeepAlive(sd)
	control, _, e := sd.Control()
	if e != nil || control&windows.SE_DACL_PRESENT == 0 || (protected && control&windows.SE_DACL_PROTECTED == 0) {
		return errNativeFile
	}
	owner, _, e := sd.Owner()
	if e != nil || owner == nil || !owner.IsValid() || !trustedNativeSID(owner.String()) {
		return errNativeFile
	}
	acl, _, e := sd.DACL()
	if e != nil || acl == nil {
		return errNativeFile
	}
	header := unsafe.Slice((*byte)(unsafe.Pointer(acl)), 8)
	size := int(binary.LittleEndian.Uint16(header[2:4]))
	if size < 8 || (header[0] != 2 && header[0] != 4) || header[1] != 0 || header[6] != 0 || header[7] != 0 {
		return errNativeFile
	}
	data := unsafe.Slice((*byte)(unsafe.Pointer(acl)), size)
	offset := 8
	for i := 0; i < int(acl.AceCount); i++ {
		if offset+4 > len(data) {
			return errNativeFile
		}
		ace := data[offset:]
		n := int(binary.LittleEndian.Uint16(ace[2:4]))
		if n < 4 || n%4 != 0 || n > len(ace) {
			return errNativeFile
		}
		ace = ace[:n]
		offset += n
		if ace[0] != windows.ACCESS_ALLOWED_ACE_TYPE && ace[0] != windows.ACCESS_DENIED_ACE_TYPE {
			if ace[1]&0x08 != 0 {
				continue
			} // Unfamiliar inherit-only ACEs are not effective here.
			return errNativeFile
		}
		if ace[1]&^byte(0x1f) != 0 || n < 16 {
			return errNativeFile
		}
		sidBytes := ace[8:]
		if sidBytes[0] != 1 || sidBytes[1] > 15 || 8+4*int(sidBytes[1]) != len(sidBytes) {
			return errNativeFile
		}
		sid := (*windows.SID)(unsafe.Pointer(&sidBytes[0]))
		if !sid.IsValid() {
			return errNativeFile
		}
		if ace[1]&0x08 != 0 {
			continue
		} // Valid inherit-only entries have no rights on this object.
		if ace[0] == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		mask := binary.LittleEndian.Uint32(ace[4:8])
		if mask&windows.GENERIC_READ != 0 {
			mask = mask&^uint32(windows.GENERIC_READ) | windows.FILE_GENERIC_READ
		}
		if mask&windows.GENERIC_EXECUTE != 0 {
			mask = mask&^uint32(windows.GENERIC_EXECUTE) | windows.FILE_GENERIC_EXECUTE
		}
		if mask&windows.GENERIC_WRITE != 0 {
			mask = mask&^uint32(windows.GENERIC_WRITE) | windows.FILE_GENERIC_WRITE
		}
		if mask&windows.GENERIC_ALL != 0 {
			mask = mask&^uint32(windows.GENERIC_ALL) | 0x1f01ff
		}
		// File and directory generic mappings share these bits (list/read,
		// traverse/execute). Only the held volume root permits child-directory creation.
		const readOnly = windows.FILE_GENERIC_READ | windows.FILE_GENERIC_EXECUTE
		allowed := uint32(readOnly)
		if policy == volumeRootPolicy {
			allowed |= 0x4 // FILE_ADD_SUBDIRECTORY; FILE_APPEND_DATA only for files.
		}
		if mask&^allowed != 0 && !trustedNativeSID(sid.String()) {
			return errNativeFile
		}
	}
	return nil
}
