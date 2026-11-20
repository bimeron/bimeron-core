package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func init() {
	requireHoldWriter = func(t *testing.T) {
		t.Helper()
		user, err := windows.GetCurrentProcessToken().GetTokenUser()
		if err != nil {
			t.Fatal(err)
		}
		if !user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
			t.Skip("requires LocalSystem in the Windows guest")
		}
	}
}

func TestUpdateHoldReplacesBroadStagingACL(t *testing.T) {
	requireHoldWriter(t)
	h := UpdateHold{Path: filepath.Join(t.TempDir(), "hold.json")}
	if err := h.Write(strings.Repeat("ab", 32)); err != nil {
		t.Fatal(err)
	}
	staged := h.Path + ".new"
	if err := os.WriteFile(staged, []byte("stale"), 0600); err != nil {
		t.Fatal(err)
	}
	broad, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := broad.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(staged, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	if err := h.Write(heldProfile); err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(h.Path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if sd.String() != holdFileSDDL || h.Read() != heldProfile {
		t.Fatal(sd.String(), h.Read())
	}
}
