//go:build windows

package testutil

import (
	"runtime"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Well-known SIDs used by Windows access tests.
const (
	AuthenticatedUsers = "S-1-5-11"
	Administrators     = "S-1-5-32-544"
)

var advapi32 = windows.NewLazySystemDLL("advapi32.dll")

// LimitedToken returns an impersonation token of the current user with the
// given groups set to deny-only, all privileges but SeChangeNotify removed and
// medium integrity. With Administrators disabled it resembles the filtered
// token of a non-elevated administrator.
func LimitedToken(t testing.TB, disable ...string) windows.Token {
	t.Helper()
	var process windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY|windows.TOKEN_ASSIGN_PRIMARY, &process); err != nil {
		t.Fatal(err)
	}
	defer process.Close()
	groups := make([]windows.SIDAndAttributes, len(disable))
	for i, s := range disable {
		sid, err := windows.StringToSid(s)
		if err != nil {
			t.Fatal(err)
		}
		groups[i].Sid = sid
	}
	var first *windows.SIDAndAttributes
	if len(groups) != 0 {
		first = &groups[0]
	}
	const disableMaxPrivilege = 1
	var restricted windows.Token
	ok, _, callErr := advapi32.NewProc("CreateRestrictedToken").Call(uintptr(process), disableMaxPrivilege, uintptr(len(groups)), uintptr(unsafe.Pointer(first)), 0, 0, 0, 0, uintptr(unsafe.Pointer(&restricted)))
	runtime.KeepAlive(groups)
	if ok == 0 {
		t.Fatal("CreateRestrictedToken failed:", callErr)
	}
	defer restricted.Close()
	var token windows.Token
	if err := windows.DuplicateTokenEx(restricted, windows.TOKEN_ALL_ACCESS, nil, windows.SecurityImpersonation, windows.TokenImpersonation, &token); err != nil {
		t.Fatal(err)
	}
	medium, err := windows.StringToSid("S-1-16-8192")
	if err != nil {
		t.Fatal(err)
	}
	label := windows.Tokenmandatorylabel{Label: windows.SIDAndAttributes{Sid: medium, Attributes: windows.SE_GROUP_INTEGRITY}}
	if err := windows.SetTokenInformation(token, windows.TokenIntegrityLevel, (*byte)(unsafe.Pointer(&label)), label.Size()); err != nil {
		token.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { token.Close() })
	return token
}

// Impersonating runs fn on one OS thread that impersonates token.
func Impersonating(t testing.TB, token windows.Token, fn func()) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if err := windows.SetThreadToken(nil, token); err != nil {
			done <- err
			return
		}
		defer func() {
			if err := windows.RevertToSelf(); err != nil {
				panic(err)
			}
			done <- nil
		}()
		fn()
	}()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// GrantedPipeRights evaluates sddl for the impersonation token as a named
// pipe object would and returns the maximum allowed access.
func GrantedPipeRights(t testing.TB, token windows.Token, sddl string) uint32 {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	mapping := [4]uint32{windows.FILE_GENERIC_READ, windows.FILE_GENERIC_WRITE, windows.FILE_GENERIC_EXECUTE, 0x001f01ff}
	// Object creation maps generic ACE rights to pipe-specific rights. A freshly
	// parsed SDDL needs that mapping before AccessCheck.
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			t.Fatal(err)
		}
		if ace.Mask&windows.GENERIC_ALL != 0 {
			ace.Mask = (ace.Mask &^ windows.GENERIC_ALL) | windows.ACCESS_MASK(mapping[3])
		}
	}
	var privileges [256]byte
	size := uint32(len(privileges))
	var granted, status uint32
	ok, _, callErr := advapi32.NewProc("AccessCheck").Call(uintptr(unsafe.Pointer(sd)), uintptr(token), windows.MAXIMUM_ALLOWED, uintptr(unsafe.Pointer(&mapping)), uintptr(unsafe.Pointer(&privileges[0])), uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&granted)), uintptr(unsafe.Pointer(&status)))
	runtime.KeepAlive(sd)
	if ok == 0 {
		t.Fatal("AccessCheck failed:", callErr)
	}
	if status == 0 {
		return 0
	}
	return granted
}
