//go:build windows

package windowsnet

import (
	"fmt"
	"golang.org/x/sys/windows"
	"unsafe"
)

// Both the installer and updated owners use this security contract. A squatted
// or legacy object with an untrusted owner/writer fails closed, never gets fixed.
func createConnectMutex(name *uint16) (windows.Handle, error) {
	sd, err := windows.SecurityDescriptorFromString("O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x00100000;;;BU)")
	if err != nil {
		return 0, err
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	h, err := windows.CreateMutex(&sa, false, name)
	if err != nil && err != windows.ERROR_ALREADY_EXISTS {
		if h != 0 {
			windows.CloseHandle(h)
		}
		return 0, err
	}
	actual, e := windows.GetSecurityInfo(h, windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if e != nil || !safeConnectDescriptor(actual) {
		windows.CloseHandle(h)
		return 0, fmt.Errorf("VPN lock security rejected")
	}
	return h, nil
}

func safeConnectDescriptor(sd *windows.SECURITY_DESCRIPTOR) bool {
	if sd == nil {
		return false
	}
	trusted := func(sid *windows.SID) bool {
		return sid != nil && (sid.String() == "S-1-5-18" || sid.String() == "S-1-5-32-544")
	}
	owner, _, err := sd.Owner()
	if err != nil || !trusted(owner) {
		return false
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		return false
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, i, &ace) != nil {
			return false
		}
		if ace.Header.AceFlags&0x8 != 0 || ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return false
		}
		// Only query/synchronize access is harmless for untrusted callers.
		if !trusted((*windows.SID)(unsafe.Pointer(&ace.SidStart))) && uint32(ace.Mask) & ^uint32(windows.READ_CONTROL|windows.SYNCHRONIZE) != 0 {
			return false
		}
	}
	return true
}
