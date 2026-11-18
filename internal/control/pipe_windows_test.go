//go:build windows

package control

import (
	core "bimeron/core"
	"context"
	"errors"
	"fmt"
	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
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
	listener, err := listenServicePipe(path, sid, sid)
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
	// Keep the client alive until Accept completes. go-winio retries Accept
	// when a client disconnects before ConnectNamedPipe finishes.
	defer conn.Close()
	select {
	case err := <-accepted:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

// countingPipe accepts every client and counts the bytes they send.
func countingPipe(l net.Listener) (*atomic.Int64, func()) {
	var read atomic.Int64
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				n, _ := io.Copy(io.Discard, c)
				read.Add(n)
			}()
		}
	}()
	return &read, func() { l.Close(); wg.Wait() }
}

func TestServicePipeIdentityBeforeWrite(t *testing.T) {
	_, sid, err := pipeIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if sid == serviceObjectOwner {
		t.Skip("test needs a non-SYSTEM owner")
	}
	path := fmt.Sprintf(`\\.\pipe\Bimeron.IdentityTest.%d`, time.Now().UnixNano())
	l, err := listenServicePipe(path, sid, sid)
	if err != nil {
		t.Fatal(err)
	}
	read, stop := countingPipe(l)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := dialServicePipe(ctx, path, pipeTrust{serviceOwner: serviceObjectOwner}); !errors.Is(err, ErrServerUntrusted) {
		t.Fatal("pipe owned by the current user accepted as service:", err)
	}
	if pid := serviceProcessID(serviceName); pid != 0 {
		if _, err := dialServicePipe(ctx, path, pipeTrust{serviceOwner: sid, service: serviceName}); !errors.Is(err, ErrServerUntrusted) {
			t.Fatal("server process other than the service accepted:", err)
		}
	}
	c, err := dialServicePipe(ctx, path, pipeTrust{serviceOwner: sid})
	if err != nil {
		t.Fatal("expected owner rejected:", err)
	}
	c.Close()
	stop()
	if n := read.Load(); n != 0 {
		t.Fatalf("server received %d bytes before identity verification", n)
	}
}

func TestDialPipesConsoleIdentity(t *testing.T) {
	path, sid, err := pipeIdentity()
	if err != nil {
		t.Fatal(err)
	}
	elevated := windows.GetCurrentProcessToken().IsElevated()
	owner := sid
	if elevated {
		owner = "BA"
	}
	stamp := time.Now().UnixNano()
	console := fmt.Sprintf("%s.console.%d", path, stamp)
	missing := fmt.Sprintf(`\\.\pipe\Bimeron.IdentityTest.Missing.%d`, stamp)
	l, err := listenConsolePipe(console, owner, sid)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- NewServer(&fakeEngine{state: core.Disconnected, events: make(chan core.Event)}).Serve(ctx, l)
	}()
	defer func() { cancel(); <-done }()
	want := pipeTrust{serviceObjectOwner, "", consoleObjectOwner, sid}
	c, err := dialPipes(ctx, missing, console, want)
	if !elevated {
		if !errors.Is(err, ErrServerUntrusted) {
			t.Fatal("non-elevated console server accepted:", err)
		}
	} else {
		if err != nil {
			t.Fatal("elevated same-user console server rejected:", err)
		}
		_, err = exchange(ctx, c, Request{Command: "status"})
		c.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	other := want
	other.user = "S-1-5-21-111-222-333-444"
	if _, err := dialPipes(ctx, missing, console, other); !errors.Is(err, ErrServerUntrusted) {
		t.Fatal("console server of another user accepted:", err)
	}

	// A rejected service endpoint must not fall back to a trusted console daemon.
	service := fmt.Sprintf(`\\.\pipe\Bimeron.IdentityTest.Service.%d`, stamp)
	sl, err := listenServicePipe(service, sid, sid)
	if err != nil {
		t.Fatal(err)
	}
	read, stop := countingPipe(sl)
	if _, err := dialPipes(ctx, service, console, want); !errors.Is(err, ErrServerUntrusted) {
		t.Fatal("untrusted service endpoint was not rejected:", err)
	}
	stop()
	if n := read.Load(); n != 0 {
		t.Fatalf("service endpoint received %d bytes", n)
	}
}
