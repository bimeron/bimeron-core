//go:build windows

package control

import (
	"bimeron/core"
	"bimeron/internal/testutil"
	"context"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"os"
	"testing"
	"time"
)

func TestReadinessWindowsACLAndServerPID(t *testing.T) {
	path := fmt.Sprintf(`\\.\pipe\Bimeron.Readiness.Test.%d.%d`, os.Getpid(), time.Now().UnixNano())
	_, sid, err := pipeIdentity()
	if err != nil {
		t.Fatal(err)
	}
	// Production reserves instance creation for SYSTEM; the test server needs it.
	l, err := listenServiceReadinessPipe(path, readinessPipeSDDL(sid)+testInstanceACE(sid))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- NewServer(core.New(core.Options{})).ServeReadiness(ctx, l) }()
	defer func() { cancel(); <-done }()
	a, err := callServiceReadinessPipe(ctx, path, uint32(os.Getpid()), Request{Command: "hello"})
	if !windows.GetCurrentProcessToken().IsElevated() {
		if !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			t.Fatalf("non-elevated user must be denied: %v", err)
		}
		return
	}
	if err != nil || a.Core == nil {
		t.Fatal(a, err)
	}
	if _, err := callServiceReadinessPipe(ctx, path, uint32(os.Getpid()+1), Request{Command: "hello"}); err == nil {
		t.Fatal("foreign server PID accepted")
	}
	if _, err := callServiceReadinessPipe(ctx, path, uint32(os.Getpid()), Request{Command: "stop"}); err == nil {
		t.Fatal("control command accepted")
	}
}

// Administrators can connect to the readiness pipe but cannot create
// instances or change its security; other principals get nothing.
func TestReadinessPipeRights(t *testing.T) {
	_, sid, err := pipeIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if sid == serviceObjectOwner {
		t.Skip("test needs a non-SYSTEM user")
	}
	sddl := readinessPipeSDDL("SYG:SY")
	if got := testutil.GrantedPipeRights(t, testutil.LimitedToken(t, administrators), sddl); got != 0 {
		t.Errorf("readiness pipe grants a non-administrator %#x", got)
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("administrator rights need an elevated test process")
	}
	const forbidden = 0x4 | windows.WRITE_DAC | windows.WRITE_OWNER
	if got := testutil.GrantedPipeRights(t, testutil.LimitedToken(t), sddl); got != 0x12019b || got&forbidden != 0 {
		t.Errorf("readiness pipe grants Administrators %#x, want 0x12019b", got)
	}
}
