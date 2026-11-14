//go:build windows

package nativeenrollment

import (
	"fmt"
	"golang.org/x/sys/windows"
	"testing"
)

func TestFileDescriptor(t *testing.T) {
	const ti = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
	for _, owner := range []string{"SY", "BA", ti} {
		for _, protected := range []bool{false, true} {
			s := "O:" + owner + "D:P(A;;FA;;;" + owner + ")(A;;GRGX;;;BU)"
			sd, e := windows.SecurityDescriptorFromString(s)
			if e != nil {
				t.Fatal(e)
			}
			if e = fileDescriptor(sd, protected); e != nil {
				t.Fatalf("trusted descriptor: %s: %v", s, e)
			}
		}
	}
	for _, tc := range []struct {
		s               string
		protected, safe bool
	}{
		{"O:BAD:(A;;GRGX;;;BU)", false, true},
		{"O:BAD:(A;;GRGX;;;BU)", true, false},
		{"O:BUD:P(A;;FA;;;SY)", true, false},
		{"O:BAD:NO_ACCESS_CONTROL", true, false},
		{"O:BA", false, false},
		{"O:BAD:P(A;IO;FA;;;BU)", true, true},
		{"O:BAD:P(A;ID;GW;;;BU)", true, false},
		{"O:BAD:P(D;;FA;;;BU)(A;;GW;;;BU)", true, false},
	} {
		sd, e := windows.SecurityDescriptorFromString(tc.s)
		if e != nil {
			t.Fatal(tc.s, e)
		}
		if (fileDescriptor(sd, tc.protected) == nil) != tc.safe {
			t.Fatalf("descriptor %s", tc.s)
		}
	}
	for _, right := range []uint32{windows.FILE_WRITE_DATA, windows.FILE_APPEND_DATA, windows.FILE_WRITE_EA, windows.FILE_WRITE_ATTRIBUTES, 0x40, windows.DELETE, windows.WRITE_DAC, windows.WRITE_OWNER, windows.GENERIC_WRITE, windows.GENERIC_ALL} {
		sd, e := windows.SecurityDescriptorFromString(fmt.Sprintf("O:BAD:P(A;;0x%x;;;BU)", right))
		if e != nil {
			t.Fatal(e)
		}
		if fileDescriptor(sd, true) == nil {
			t.Fatalf("accepted mutation %x", right)
		}
	}
	if fileDescriptor(nil, true) == nil {
		t.Fatal("nil descriptor accepted")
	}
	sd, e := windows.NewSecurityDescriptor()
	if e != nil {
		t.Fatal(e)
	}
	if fileDescriptor(sd, true) == nil {
		t.Fatal("missing owner/DACL accepted")
	}
	if fileObjectSecurity(windows.InvalidHandle, true) == nil {
		t.Fatal("descriptor query failure accepted")
	}
	unknown, e := windows.SecurityDescriptorFromString("O:BAD:P(A;;GR;;;BU)")
	if e != nil {
		t.Fatal(e)
	}
	acl, _, e := unknown.DACL()
	if e != nil {
		t.Fatal(e)
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if e = windows.GetAce(acl, 0, &ace); e != nil {
		t.Fatal(e)
	}
	ace.Header.AceType = 9 // An effective callback ACE is deliberately unfamiliar.
	if fileDescriptor(unknown, true) == nil {
		t.Fatal("unknown effective ACE accepted")
	}
}

// Exact parent-supplied core-reader-clean-metadata.json descriptors, not captured here.
const capturedVolumeRootSDDL = `O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;;LC;;;AU)(A;OICIIO;SDGXGWGR;;;AU)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)`
const capturedProgramFilesSDDL = `O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;OICIIO;GA;;;CO)(A;OICIIO;GA;;;SY)(A;;0x1301bf;;;SY)(A;OICIIO;GA;;;BA)(A;;0x1301bf;;;BA)(A;OICIIO;GXGR;;;BU)(A;;0x1200a9;;;BU)(A;CIIO;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;0x1200a9;;;AC)(A;OICIIO;GXGR;;;AC)(A;;0x1200a9;;;S-1-15-2-2)(A;OICIIO;GXGR;;;S-1-15-2-2)`

func TestCapturedVolumeRootDescriptor(t *testing.T) {
	sd, err := windows.SecurityDescriptorFromString(capturedVolumeRootSDDL)
	if err != nil {
		t.Fatal(err)
	}
	if err := fileDescriptorPolicy(sd, false, volumeRootPolicy); err != nil {
		t.Fatalf("captured root rejected: %v", err)
	}
	if fileDescriptor(sd, false) == nil || fileDescriptor(sd, true) == nil {
		t.Fatal("captured root accepted by strict Program Files/descendant policy")
	}
	pf, err := windows.SecurityDescriptorFromString(capturedProgramFilesSDDL)
	if err != nil {
		t.Fatal(err)
	}
	if fileDescriptor(pf, false) != nil || fileDescriptor(pf, true) != nil {
		t.Fatal("actual Program Files descriptor rejected by strict policy")
	}
}

func TestVolumeRootDescriptorPolicy(t *testing.T) {
	for _, flags := range []string{"", "ID"} {
		for _, mask := range []uint32{4, 4 | windows.FILE_GENERIC_READ | windows.FILE_GENERIC_EXECUTE} {
			sd, err := windows.SecurityDescriptorFromString(fmt.Sprintf("O:BAD:(A;%s;0x%x;;;AU)", flags, mask))
			if err != nil {
				t.Fatal(err)
			}
			if fileDescriptorPolicy(sd, false, volumeRootPolicy) != nil {
				t.Fatalf("safe root flags=%s mask=%x", flags, mask)
			}
			if fileDescriptor(sd, false) == nil {
				t.Fatal("root allowance leaked to ordinary descriptor")
			}
		}
	}
	for _, right := range []uint32{windows.FILE_WRITE_DATA, windows.FILE_WRITE_EA, windows.FILE_WRITE_ATTRIBUTES, 0x40, windows.DELETE, windows.WRITE_DAC, windows.WRITE_OWNER, windows.GENERIC_WRITE, windows.GENERIC_ALL, 0x200} {
		for _, flags := range []string{"", "ID"} {
			for _, mask := range []uint32{right, right | 4} {
				sd, err := windows.SecurityDescriptorFromString(fmt.Sprintf("O:BAD:P(D;;FA;;;AU)(A;%s;0x%x;;;AU)", flags, mask))
				if err != nil {
					t.Fatal(err)
				}
				if fileDescriptorPolicy(sd, false, volumeRootPolicy) == nil {
					t.Fatalf("root mutation accepted flags=%s mask=%x", flags, mask)
				}
			}
		}
	}
	for _, s := range []string{"O:BUD:P(A;;LC;;;AU)", "O:BA", "O:BAD:NO_ACCESS_CONTROL"} {
		sd, err := windows.SecurityDescriptorFromString(s)
		if err != nil {
			t.Fatal(err)
		}
		if fileDescriptorPolicy(sd, false, volumeRootPolicy) == nil {
			t.Fatalf("unsafe root descriptor accepted: %s", s)
		}
	}
	if fileDescriptorPolicy(nil, false, volumeRootPolicy) == nil {
		t.Fatal("nil root accepted")
	}
	sd, err := windows.SecurityDescriptorFromString("O:BAD:(A;IO;GA;;;AU)(A;;LC;;;AU)")
	if err != nil {
		t.Fatal(err)
	}
	if fileDescriptorPolicy(sd, false, volumeRootPolicy) != nil {
		t.Fatal("inherit-only treatment changed")
	}
	if fileDescriptorPolicy(sd, true, volumeRootPolicy) == nil {
		t.Fatal("protected DACL requirement lost")
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(acl, 1, &ace); err != nil {
		t.Fatal(err)
	}
	ace.Header.AceType = 9
	if fileDescriptorPolicy(sd, false, volumeRootPolicy) == nil {
		t.Fatal("unknown effective root ACE accepted")
	}
}
