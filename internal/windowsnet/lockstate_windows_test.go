//go:build windows

package windowsnet

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The session lock state is read without taking the lock: a missing or free
// lock is not held, a lock owned by another thread is, and an abandoned lock
// is not held and stays abandoned for the next acquirer.
func TestSessionLockHeldDoesNotAcquire(t *testing.T) {
	if name := os.Getenv("BIMERON_TEST_ABANDON_MUTEX"); name != "" {
		runtime.LockOSThread()
		p, _ := windows.UTF16PtrFromString(name)
		h, err := windows.OpenMutex(windows.SYNCHRONIZE, false, p)
		if err != nil {
			t.Fatal(err)
		}
		if s, err := windows.WaitForSingleObject(h, 0); err != nil || s != windows.WAIT_OBJECT_0 {
			t.Fatal("child did not acquire the lock", s, err)
		}
		os.Exit(0) // Deliberately abandon only this isolated test mutex.
	}
	if !Elevated() {
		t.Skip("protected administrator-owned mutex fixture requires elevation")
	}
	name := fmt.Sprintf(`Local\Bimeron.LockState.Test.%d.%d`, os.Getpid(), time.Now().UnixNano())
	marker := name + ".Owner"
	if held, err := sessionLockHeld(name, marker); held || err != nil {
		t.Fatal("missing lock", held, err)
	}
	n, _ := windows.UTF16PtrFromString(name)
	h, err := createConnectMutex(n)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	if held, err := sessionLockHeld(name, marker); held || err != nil {
		t.Fatal("free lock", held, err)
	}
	acquired, released := make(chan struct{}), make(chan struct{})
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if s, err := windows.WaitForSingleObject(h, 0); err != nil || s != windows.WAIT_OBJECT_0 {
			t.Error("owner could not take the lock", s, err)
		}
		close(acquired)
		<-released
		windows.ReleaseMutex(h)
		close(released)
	}()
	<-acquired
	if held, err := sessionLockHeld(name, marker); !held || err != nil {
		t.Fatal("owned lock", held, err)
	}
	released <- struct{}{}
	<-released
	// An owner process that exits without releasing abandons the lock.
	child := exec.Command(os.Args[0], "-test.run=^TestSessionLockHeldDoesNotAcquire$")
	child.Env = append(os.Environ(), "BIMERON_TEST_ABANDON_MUTEX="+name)
	if out, err := child.CombinedOutput(); err != nil {
		t.Fatalf("abandon fixture: %v %s", err, out)
	}
	if info, err := queryMutant(h); err != nil || info.AbandonedState == 0 || info.CurrentCount != 1 {
		t.Fatal("owner process did not abandon the lock", info, err)
	}
	for range 3 {
		if held, err := sessionLockHeld(name, marker); held || err != nil {
			t.Fatal("abandoned lock", held, err)
		}
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	s, err := windows.WaitForSingleObject(h, 0)
	if err != nil || s != windows.WAIT_ABANDONED {
		t.Fatal("the probe cleared the abandoned state", s, err)
	}
	windows.ReleaseMutex(h)
}

// A live foreground owner marker means the session is owned, even while the
// lock is free; an existing lock object with an unsafe descriptor proves
// nothing about its owner and is refused.
func TestSessionLockHeldHonorsMarkerAndSecurity(t *testing.T) {
	if !Elevated() {
		t.Skip("protected administrator-owned mutex fixture requires elevation")
	}
	name := fmt.Sprintf(`Local\Bimeron.LockState.Marker.%d.%d`, os.Getpid(), time.Now().UnixNano())
	marker := name + ".Owner"
	n, _ := windows.UTF16PtrFromString(name)
	h, err := createConnectMutex(n)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	m, _ := windows.UTF16PtrFromString(marker)
	owner, err := windows.CreateMutex(nil, false, m)
	if err != nil {
		t.Fatal(err)
	}
	if held, err := sessionLockHeld(name, marker); !held || err != nil {
		t.Fatal("foreground owner marker ignored", held, err)
	}
	windows.CloseHandle(owner)
	if held, err := sessionLockHeld(name, marker); held || err != nil {
		t.Fatal("free lock without marker", held, err)
	}
	unsafeName := name + ".Unsafe"
	sd, _ := windows.SecurityDescriptorFromString("O:BAG:BAD:P(A;;GA;;;WD)")
	sa := windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(sa))
	u, _ := windows.UTF16PtrFromString(unsafeName)
	bad, err := windows.CreateMutex(&sa, false, u)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(bad)
	if held, err := sessionLockHeld(unsafeName, marker); held || err == nil {
		t.Fatal("unsafe lock object trusted", held, err)
	}
}
