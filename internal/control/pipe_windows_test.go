//go:build windows

package control

import (
	"context"
	"fmt"
	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
	core "bimeron/core"
	"runtime"
	"testing"
	"time"
	"unsafe"
)

func TestNativePipeControl(t *testing.T) {
	path, sid, err := pipeIdentity()
	if err != nil {
		t.Fatal(err)
	}
	path += fmt.Sprintf(".test.%d", time.Now().UnixNano())
	cfg := &winio.PipeConfig{SecurityDescriptor: "D:P(A;;GA;;;SY)(A;;GA;;;" + sid + ")"}
	l, err := winio.ListenPipe(path, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if second, err := winio.ListenPipe(path, cfg); err == nil {
		second.Close()
		t.Fatal("duplicate daemon allowed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	e := &fakeEngine{state: core.Disconnected, events: make(chan core.Event)}
	done := make(chan error, 1)
	go func() { done <- NewServer(e).Serve(ctx, l) }()
	for _, command := range []string{"status", "stop", "status", "shutdown"} {
		c, err := winio.DialPipeContext(ctx, path)
		if err != nil {
			t.Fatal(err)
		}
		_, err = exchange(ctx, c, Request{Command: command})
		c.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("daemon did not exit")
	}
}

func TestServicePipeOwnerAndForeignACL(t *testing.T) {
	t.Logf("owner process elevated: %t", windows.GetCurrentProcessToken().IsElevated())
	_, sid, err := pipeIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if sid == "S-1-5-18" {
		t.Skip("SYSTEM is intentionally always allowed")
	}
	var token windows.Token
	var processToken windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY, &processToken); err != nil {
		t.Fatal(err)
	}
	defer processToken.Close()
	if err := windows.DuplicateTokenEx(processToken, windows.TOKEN_QUERY, nil, windows.SecurityImpersonation, windows.TokenImpersonation, &token); err != nil {
		t.Fatal(err)
	}
	defer token.Close()
	accessCheck := windows.NewLazySystemDLL("advapi32.dll").NewProc("AccessCheck")
	for _, allowed := range []bool{true, false} {
		owner := sid
		if !allowed {
			owner = "S-1-5-21-111-222-333-444"
		}
		dacl, err := servicePipeDACL(owner)
		if err != nil {
			t.Fatal(err)
		}
		sd, err := windows.SecurityDescriptorFromString("O:" + sid + "G:" + sid + dacl)
		if err != nil {
			t.Fatal(err)
		}
		mapping := [4]uint32{windows.FILE_GENERIC_READ, windows.FILE_GENERIC_WRITE, windows.FILE_GENERIC_EXECUTE, 0x001f01ff}
		// Object creation maps generic ACE rights to file/pipe-specific rights.
		// AccessCheck on a freshly parsed SDDL requires that mapping explicitly.
		acl, _, err := sd.DACL()
		if err != nil {
			t.Fatal(err)
		}
		for i := uint32(0); i < 2; i++ {
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
		ok, _, callErr := accessCheck.Call(uintptr(unsafe.Pointer(sd)), uintptr(token), uintptr(windows.FILE_GENERIC_READ|windows.FILE_GENERIC_WRITE), uintptr(unsafe.Pointer(&mapping)), uintptr(unsafe.Pointer(&privileges[0])), uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&granted)), uintptr(unsafe.Pointer(&status)))
		runtime.KeepAlive(sd)
		if ok == 0 {
			t.Fatal("AccessCheck failed", callErr)
		}
		if (status != 0) != allowed {
			t.Fatalf("owner allowed=%t; OS permission result=%d", allowed, status)
		}
	}
	path := fmt.Sprintf(`\\.\pipe\Bimeron.AccessTest.%d`, time.Now().UnixNano())
	listener, err := listenServicePipe(path, sid)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if conn != nil {
			conn.Close()
		}
		accepted <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := winio.DialPipeContext(ctx, path)
	if err != nil {
		t.Fatal("owner rejected", err)
	}
	conn.Close()
	select {
	case err := <-accepted:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}
