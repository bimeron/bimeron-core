//go:build windows

package control

import (
	"bimeron/core"
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
	l, err := listenServiceReadinessPipe(path)
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
