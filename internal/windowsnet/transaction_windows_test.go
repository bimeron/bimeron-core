//go:build windows

package windowsnet

import (
	"fmt"
	"golang.org/x/sys/windows"
	"os"
	"os/exec"
	"runtime"
	"testing"
	"time"
	"unsafe"
)

func TestInstallationMutexSecurity(t *testing.T) {
	for _, tc := range []struct {
		sddl string
		safe bool
	}{
		{"O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x00100000;;;BU)", true},
		{"O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)", true},
		{"O:BUG:BAD:P(A;;GA;;;BA)", false},
		{"O:BAG:BAD:P(A;;GA;;;WD)", false},
		{"O:BAG:BAD:P(A;;0x00000001;;;BU)", false},
		{"O:BAG:BAD:P(A;;WD;;;BU)", false},
		{"O:BAG:BAD:NO_ACCESS_CONTROL", false},
	} {
		sd, err := windows.SecurityDescriptorFromString(tc.sddl)
		if err != nil {
			t.Fatal(err)
		}
		if safeConnectDescriptor(sd) != tc.safe {
			t.Fatalf("wrong decision for %s", tc.sddl)
		}
	}
}

func transactionNames(t *testing.T) (string, string) {
	t.Helper()
	if !Elevated() {
		t.Skip("protected administrator-owned mutex fixture requires elevation")
	}
	base := fmt.Sprintf(`Local\Bimeron.Transaction.Test.%d.%d`, os.Getpid(), time.Now().UnixNano())
	return base, base + ".Owner"
}

func TestInstallationTransactionExcludesStartingOwnersAndPacketHosts(t *testing.T) {
	connect, marker := transactionNames(t)
	release, err := acquireConnectNamed(connect, marker, false, true)
	if err != nil {
		t.Fatal(err)
	}
	// Different goroutines execute on different OS threads while the holder is pinned.
	result := make(chan error, 1)
	go func() {
		r, e := beginForegroundOwnership(connect, marker)
		if e == nil {
			r()
		}
		result <- e
	}()
	if e := <-result; e == nil {
		release()
		t.Fatal("foreground admitted during replacement")
	}
	go func() {
		r, e := acquireConnectNamed(connect, marker, true, false)
		if e == nil {
			r()
		}
		result <- e
	}()
	if e := <-result; e == nil {
		release()
		t.Fatal("packet host admitted during replacement")
	}
	release()
	owner, err := beginForegroundOwnership(connect, marker)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { owner() }()
	// Installer never uses the same-process foreground exception.
	if r, e := acquireConnectNamed(connect, marker, false, true); e == nil {
		r()
		t.Fatal("installer admitted with lifetime marker")
	}
	owner()
	owner = func() {}
	r, e := acquireConnectNamed(connect, marker, false, true)
	if e != nil {
		t.Fatal(e)
	}
	r()
}

func TestInstallationTransactionRefusesAbandonedAndUnsafeExistingObjects(t *testing.T) {
	if name := os.Getenv("BIMERON_TEST_ABANDON_MUTEX"); name != "" {
		runtime.LockOSThread()
		p, _ := windows.UTF16PtrFromString(name)
		h, e := windows.OpenMutex(windows.SYNCHRONIZE|1, false, p)
		if e != nil {
			t.Fatal(e)
		}
		status, e := windows.WaitForSingleObject(h, 0)
		if e != nil || status != windows.WAIT_OBJECT_0 {
			t.Fatal("child did not acquire mutex")
		}
		os.Exit(0) // Deliberately abandon only this isolated test mutex.
	}
	connect, marker := transactionNames(t)
	name, _ := windows.UTF16PtrFromString(connect)
	h, err := createConnectMutex(name)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	child := exec.Command(os.Args[0], "-test.run=^TestInstallationTransactionRefusesAbandonedAndUnsafeExistingObjects$")
	child.Env = append(os.Environ(), "BIMERON_TEST_ABANDON_MUTEX="+connect)
	if out, e := child.CombinedOutput(); e != nil {
		t.Fatalf("abandon fixture: %v %s", e, out)
	}
	if r, e := acquireConnectNamed(connect, marker, false, true); e == nil {
		r()
		t.Fatal("accepted abandoned transaction")
	} else if e.Error() != "installation transaction abandoned; manual review required" {
		t.Fatal(e)
	}
	unsafeName, _ := windows.UTF16PtrFromString(connect + ".Unsafe")
	sd, _ := windows.SecurityDescriptorFromString("O:BAG:BAD:P(A;;GA;;;WD)")
	sa := windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(sa))
	bad, e := windows.CreateMutex(&sa, false, unsafeName)
	if e != nil {
		t.Fatal(e)
	}
	defer windows.CloseHandle(bad)
	if opened, e := createConnectMutex(unsafeName); e == nil {
		windows.CloseHandle(opened)
		t.Fatal("unsafe existing object accepted")
	}
}

func TestInstallationTransactionUnknownMarkerRefusesAdmission(t *testing.T) {
	connect, marker := transactionNames(t)
	name, _ := windows.UTF16PtrFromString(marker)
	event, e := windows.CreateEvent(nil, 0, 0, name)
	if e != nil {
		t.Fatal(e)
	}
	defer windows.CloseHandle(event)
	if r, e := acquireConnectNamed(connect, marker, false, true); e == nil {
		r()
		t.Fatal("wrong-type marker treated as absent")
	}
	if r, e := beginForegroundOwnership(connect, marker); e == nil {
		r()
		t.Fatal("squatted marker accepted")
	}
}
