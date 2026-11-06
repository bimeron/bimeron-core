//go:build windows

package control

import (
	"context"
	"errors"
	"fmt"
	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestForegroundLockPreservesMissingPathCause(t *testing.T) {
	directory := t.TempDir()
	for _, path := range []string{filepath.Join(directory, "missing.json"), filepath.Join(directory, "missing", "record.json")} {
		file, err := openLocked(path, false)
		if file != nil {
			file.Close()
			t.Fatal("opened absent record")
		}
		if !errors.Is(err, errForegroundIdentity) ||
			(!errors.Is(err, windows.ERROR_FILE_NOT_FOUND) && !errors.Is(err, windows.ERROR_PATH_NOT_FOUND)) {
			t.Fatalf("lost identity or absence classification: %v", err)
		}
	}

	path := filepath.Join(directory, "busy.json")
	if err := os.WriteFile(path, []byte("record"), 0600); err != nil {
		t.Fatal(err)
	}
	writer, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	file, err := openLocked(path, false)
	if file != nil {
		file.Close()
		t.Fatal("opened a record with an active writer")
	}
	if !errors.Is(err, errForegroundIdentity) || !errors.Is(err, windows.ERROR_SHARING_VIOLATION) ||
		errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
		t.Fatalf("sharing violation treated as absence: %v", err)
	}
}

func TestRepairLocksPreserveOptionalRecordAbsence(t *testing.T) {
	root, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Read-only checks beneath the real protected root; no files are created.
	absent := filepath.Join(root, fmt.Sprintf("Bimeron.Absent.%d.%d", os.Getpid(), time.Now().UnixNano()))
	for _, lock := range []func(string) (func(), error){LockRepairDirectory, LockRepairImage} {
		release, err := lock(absent)
		if release != nil {
			release()
			t.Fatal("locked absent optional record")
		}
		if !errors.Is(err, errForegroundIdentity) || !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			t.Fatalf("protected lock lost optional-record absence: %v", err)
		}
	}
}

func TestForegroundDescriptorRejectsWritableOrUserOwnedImage(t *testing.T) {
	for _, test := range []struct {
		sddl string
		safe bool
	}{
		{"O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GRGX;;;BU)", true},
		{"O:BAG:BAD:P(A;;FA;;;WD)", false},
		{"O:BAG:BAD:P(A;;GW;;;BU)", false},
		{"O:BUG:BAD:P(A;;FA;;;SY)(A;;GRGX;;;BU)", false},
	} {
		sd, err := windows.SecurityDescriptorFromString(test.sddl)
		if err != nil {
			t.Fatal(err)
		}
		if (protectedDescriptor(sd) == nil) != test.safe {
			t.Fatalf("wrong ACL decision for %s", test.sddl)
		}
	}
}

func TestForegroundPipeSquattingAndOSPeerPID(t *testing.T) {
	_, sid, err := pipeIdentity()
	if err != nil {
		t.Fatal(err)
	}
	path := fmt.Sprintf(`\\.\pipe\Bimeron.Foreground.Test.%d.%d`, os.Getpid(), time.Now().UnixNano())
	cfg := &winio.PipeConfig{SecurityDescriptor: "D:P(A;;GA;;;SY)(A;;GA;;;" + sid + ")S:(ML;;NW;;;ME)"}
	l, err := winio.ListenPipe(path, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if duplicate, e := winio.ListenPipe(path, cfg); e == nil {
		duplicate.Close()
		t.Fatal("squatted pipe accepted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		c, e := l.Accept()
		if e != nil {
			result <- e
			return
		}
		defer c.Close()
		var pid uint32
		e = windows.GetNamedPipeClientProcessId(windows.Handle(c.(interface{ Fd() uintptr }).Fd()), &pid)
		if e == nil && pid != uint32(os.Getpid()) {
			e = fmt.Errorf("wrong client PID")
		}
		result <- e
	}()
	c, err := winio.DialPipeAccessImpLevel(ctx, path, windows.GENERIC_READ|windows.GENERIC_WRITE, winio.PipeImpLevelIdentification)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var pid uint32
	if err := windows.GetNamedPipeServerProcessId(windows.Handle(c.(interface{ Fd() uintptr }).Fd()), &pid); err != nil || pid != uint32(os.Getpid()) {
		t.Fatal("wrong server PID", err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestForegroundLocksConfigAndRejectsWritableProcess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "native.conf")
	if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := openLocked(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := os.WriteFile(path, []byte("substitution"), 0600); err == nil {
		t.Fatal("locked snapshot overwritten")
	}
	if err := os.Remove(path); err == nil {
		t.Fatal("locked snapshot deleted")
	}
	if _, release, err := inspectProcess(uint32(os.Getpid())); err == nil {
		release()
		t.Fatal("user-writable test executable trusted")
	}
}

func TestForegroundSafeProfileDiagnostics(t *testing.T) {
	for _, message := range []string{"private password", "ikev2_secret_sentinel"} {
		if safeProfileCode(fmt.Errorf("%s", message)) != "ikev2_profile_operation_failed" {
			t.Fatal("untrusted diagnostic escaped")
		}
	}
}

func TestForegroundConfigPinsAncestorsAndRejectsRemoteDeviceStreams(t *testing.T) {
	for _, path := range []string{`\\untrusted.invalid\share\native.conf`, `\\.\pipe\untrusted`, `C:\native.conf:stream`, "relative.conf"} {
		if _, release, err := lockForegroundConfig(path); err == nil {
			release()
			t.Fatal("unsafe config path accepted")
		}
	}
	parent := t.TempDir()
	path := filepath.Join(parent, "native.conf")
	if err := os.WriteFile(path, []byte("reviewed"), 0600); err != nil {
		t.Fatal(err)
	}
	_, release, err := lockForegroundConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if os.Rename(parent, parent+"-substitution") == nil {
		t.Fatal("pinned config parent replaced")
	}
	if os.WriteFile(path, []byte("changed"), 0600) == nil {
		t.Fatal("pinned config bytes changed")
	}
}
