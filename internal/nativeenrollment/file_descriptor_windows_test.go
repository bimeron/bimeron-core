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
