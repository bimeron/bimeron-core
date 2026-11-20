package core

import (
	"context"
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
	h := UpdateHold{Path: filepath.Join(t.TempDir(), "hold.json"), filterGeneration: testFilterGeneration}
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

// Both services see the same persistent filters. A denied marker deletion
// and a standalone owner that never opens the marker must fail identically.
func TestReplacementRulesCannotConfirmOldMarker(t *testing.T) {
	requireHoldWriter(t)
	for _, standalone := range []bool{false, true} {
		generation := "A"
		h := &UpdateHold{Path: filepath.Join(t.TempDir(), "hold.json"), filterGeneration: func() (string, error) { return generation, nil }}
		if err := h.Write(heldProfile); err != nil {
			t.Fatal(err)
		}
		if !standalone {
			name, err := windows.UTF16PtrFromString(h.Path)
			if err != nil {
				t.Fatal(err)
			}
			handle, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer windows.CloseHandle(handle)
			if err := h.Clear(); err == nil {
				t.Fatal("expected marker consumption failure")
			}
		}
		b := &protectedBackend{fakeBackend: fakeBackend{open: func(context.Context) (session, error) { return fakeSession{}, nil }}}
		owner := testEngine(b)
		if !standalone {
			owner.opts.UpdateHold = h
		}
		generation = "B"
		ctx := testDeadline(t)
		if err := owner.Start(ctx, killSwitchConfig()); err != nil {
			t.Fatal(err)
		}
		owner.MarkAbandon()
		if err := owner.Stop(ctx); err != nil {
			t.Fatal(err)
		}
		if _, _, _, installed := b.snapshot(); !installed {
			t.Fatal("replacement owner did not retain filters")
		}
		observer := testEngine(b)
		observer.opts.UpdateHold = h
		observer.opts.ResidualProtection = true
		observer.residualProbe = func() (bool, error) { return true, nil }
		status := observer.Status()
		if status.KillSwitch != KillSwitchResidual || status.ResidualProfile != "" || status.ResidualReason != "" {
			t.Fatal(standalone, status)
		}
		if _, err := os.Stat(h.Path); err != nil {
			t.Fatal(err)
		}
	}
}
