//go:build windows

package windowsnet

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// mutantQueryState is MUTANT_QUERY_STATE, the right to read a mutex's state.
const mutantQueryState = 0x0001

var procNtQueryMutant = windows.NewLazySystemDLL("ntdll.dll").NewProc("NtQueryMutant")

// mutantBasicInformation is MUTANT_BASIC_INFORMATION (MutantBasicInformation
// class 0 of NtQueryMutant).
type mutantBasicInformation struct {
	CurrentCount   int32
	OwnedByCaller  uint8
	AbandonedState uint8
}

// SessionLockHeld reports whether an owner currently holds the VPN session:
// the session lock is held, or a foreground owner (the native IKEv2 owner
// that Desktop starts) is alive, as Acquire treats its marker. The lock is inspected
// without being taken: taking it would clear its abandoned state, which
// BeginInstallationTransaction relies on, and would briefly make a starting
// owner fail to take it. An abandoned lock is not held.
func SessionLockHeld() (bool, error) { return sessionLockHeld(connectMutex, foregroundOwnerMutex) }

func sessionLockHeld(name, marker string) (bool, error) {
	// The foreground owner keeps its marker for its whole lifetime, also while
	// it retains protection without holding the lock. Like Acquire, treat a
	// marker that exists or cannot be checked as an owner, unless it is this
	// process's own.
	if !foregroundProcess.Load() {
		m, err := windows.UTF16PtrFromString(marker)
		if err != nil {
			return false, err
		}
		owner, err := windows.OpenMutex(windows.SYNCHRONIZE, false, m)
		if owner != 0 {
			windows.CloseHandle(owner)
		}
		if !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			return true, nil
		}
	}
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return false, err
	}
	h, err := windows.OpenMutex(mutantQueryState|windows.READ_CONTROL, false, n)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		// No process has the lock open, so nobody holds it.
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("open VPN lock: %w", err)
	}
	defer windows.CloseHandle(h)
	// A squatted object proves nothing about the owner; fail closed as Acquire does.
	sd, err := windows.GetSecurityInfo(h, windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || !safeConnectDescriptor(sd) {
		return false, fmt.Errorf("VPN lock security rejected")
	}
	state, err := queryMutant(h)
	if err != nil {
		return false, err
	}
	// A free (or abandoned) mutex is signaled with a count of 1; an owned one
	// counts down from 0 for each recursive acquisition.
	return state.CurrentCount <= 0, nil
}

func queryMutant(h windows.Handle) (mutantBasicInformation, error) {
	var info mutantBasicInformation
	var size uint32
	status, _, _ := procNtQueryMutant.Call(uintptr(h), 0, uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info), uintptr(unsafe.Pointer(&size)))
	if uint32(status) != 0 {
		return mutantBasicInformation{}, fmt.Errorf("query VPN lock state: NTSTATUS 0x%08x", uint32(status))
	}
	return info, nil
}
