//go:build windows

package control

import (
	core "bimeron/core"
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
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

const (
	authenticatedUsers = "S-1-5-11"
	administrators     = "S-1-5-32-544"
	foreignUser        = "S-1-5-21-111-222-333-444"
)

// testInstanceACE lets a test server that runs as an ordinary user create the
// pipe instances that production SDDL reserves for SYSTEM or Administrators.
func testInstanceACE(sid string) string { return "(A;;" + pipeInstanceRight + ";;;" + sid + ")" }

// limitedToken returns an impersonation token of the current user with the
// given groups set to deny-only, all privileges but SeChangeNotify removed and
// medium integrity. With Administrators disabled it resembles the filtered
// token of a non-elevated administrator.
func limitedToken(t *testing.T, disable ...string) windows.Token {
	t.Helper()
	var process windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY|windows.TOKEN_ASSIGN_PRIMARY, &process); err != nil {
		t.Fatal(err)
	}
	defer process.Close()
	groups := make([]windows.SIDAndAttributes, len(disable))
	for i, s := range disable {
		sid, err := windows.StringToSid(s)
		if err != nil {
			t.Fatal(err)
		}
		groups[i].Sid = sid
	}
	const disableMaxPrivilege = 1
	var restricted windows.Token
	ok, _, callErr := windows.NewLazySystemDLL("advapi32.dll").NewProc("CreateRestrictedToken").Call(uintptr(process), disableMaxPrivilege, uintptr(len(groups)), uintptr(unsafe.Pointer(&groups[0])), 0, 0, 0, 0, uintptr(unsafe.Pointer(&restricted)))
	runtime.KeepAlive(groups)
	if ok == 0 {
		t.Fatal("CreateRestrictedToken failed:", callErr)
	}
	defer restricted.Close()
	var token windows.Token
	if err := windows.DuplicateTokenEx(restricted, windows.TOKEN_ALL_ACCESS, nil, windows.SecurityImpersonation, windows.TokenImpersonation, &token); err != nil {
		t.Fatal(err)
	}
	medium, err := windows.StringToSid("S-1-16-8192")
	if err != nil {
		t.Fatal(err)
	}
	label := windows.Tokenmandatorylabel{Label: windows.SIDAndAttributes{Sid: medium, Attributes: windows.SE_GROUP_INTEGRITY}}
	if err := windows.SetTokenInformation(token, windows.TokenIntegrityLevel, (*byte)(unsafe.Pointer(&label)), label.Size()); err != nil {
		token.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { token.Close() })
	return token
}

// impersonating runs fn on one OS thread that impersonates token.
func impersonating(t *testing.T, token windows.Token, fn func()) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if err := windows.SetThreadToken(nil, token); err != nil {
			done <- err
			return
		}
		defer func() {
			if err := windows.RevertToSelf(); err != nil {
				panic(err)
			}
			done <- nil
		}()
		fn()
	}()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// grantedPipeRights evaluates sddl for token as a named pipe object would.
func grantedPipeRights(t *testing.T, token windows.Token, sddl string) uint32 {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	mapping := [4]uint32{windows.FILE_GENERIC_READ, windows.FILE_GENERIC_WRITE, windows.FILE_GENERIC_EXECUTE, 0x001f01ff}
	// Object creation maps generic ACE rights to pipe-specific rights. A freshly
	// parsed SDDL needs that mapping before AccessCheck.
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
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
	ok, _, callErr := windows.NewLazySystemDLL("advapi32.dll").NewProc("AccessCheck").Call(uintptr(unsafe.Pointer(sd)), uintptr(token), windows.MAXIMUM_ALLOWED, uintptr(unsafe.Pointer(&mapping)), uintptr(unsafe.Pointer(&privileges[0])), uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&granted)), uintptr(unsafe.Pointer(&status)))
	runtime.KeepAlive(sd)
	if ok == 0 {
		t.Fatal("AccessCheck failed:", callErr)
	}
	if status == 0 {
		return 0
	}
	return granted
}

func TestPipeOwnerUserRights(t *testing.T) {
	_, sid, err := pipeIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if sid == serviceObjectOwner {
		t.Skip("test needs a non-SYSTEM user")
	}
	user := limitedToken(t, administrators)
	service, err := servicePipeSDDL("SYG:SY", sid)
	if err != nil {
		t.Fatal(err)
	}
	foreignService, err := servicePipeSDDL("SYG:SY", foreignUser)
	if err != nil {
		t.Fatal(err)
	}
	foreground := strings.Replace(foregroundPipeSDDL(sid), "O:BA", "O:BAG:BA", 1)
	for name, sddl := range map[string]string{"service": service, "console": consolePipeSDDL("BAG:BA", sid), "foreground": foreground} {
		const forbidden = 0x4 | windows.WRITE_DAC | windows.WRITE_OWNER
		if got := grantedPipeRights(t, user, sddl); got != 0x12019b || got&forbidden != 0 {
			t.Errorf("%s pipe grants the owner user %#x, want 0x12019b", name, got)
		}
	}
	if got := grantedPipeRights(t, user, foreignService); got != 0 {
		t.Errorf("service pipe grants another user %#x", got)
	}
	if got := grantedPipeRights(t, user, consolePipeSDDL("BAG:BA", foreignUser)); got != 0 {
		t.Errorf("console pipe grants another user %#x", got)
	}
}

// The owner user can connect to the service pipe but cannot serve it.
func TestServicePipeOwnerCannotServe(t *testing.T) {
	_, sid, err := pipeIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if sid == serviceObjectOwner {
		t.Skip("test needs a non-SYSTEM user")
	}
	sddl, err := servicePipeSDDL(sid, sid)
	if err != nil {
		t.Fatal(err)
	}
	path := fmt.Sprintf(`\\.\pipe\Bimeron.AccessTest.%d`, time.Now().UnixNano())
	l, err := listenPipe(path, sddl)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if c, err := l.Accept(); !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		if c != nil {
			c.Close()
		}
		t.Fatal("owner user created a service pipe instance:", err)
	}
	ptr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateNamedPipe(ptr, windows.PIPE_ACCESS_DUPLEX, 0, windows.PIPE_UNLIMITED_INSTANCES, 512, 512, 0, nil)
	if err == nil {
		windows.CloseHandle(h)
	}
	if !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatal("owner user created a service pipe instance:", err)
	}

	// A client with only the owner user rights connects, reads the owner,
	// writes and reads. Authenticated Users stands in for the server.
	path += ".client"
	l, err = listenPipe(path, sddl+testInstanceACE(authenticatedUsers))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		b := make([]byte, 1)
		if _, err := c.Read(b); err == nil {
			c.Write(b)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var owner string
	var clientErr error
	impersonating(t, limitedToken(t, administrators, authenticatedUsers), func() {
		c, err := winio.DialPipeContext(ctx, path)
		if err != nil {
			clientErr = err
			return
		}
		defer c.Close()
		if owner, clientErr = pipeOwner(c); clientErr != nil {
			return
		}
		if _, clientErr = c.Write([]byte{1}); clientErr == nil {
			_, clientErr = io.ReadFull(c, make([]byte, 1))
		}
	})
	if clientErr != nil || owner != sid {
		t.Fatal("owner user client failed:", owner, clientErr)
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

// withServiceProcessID replaces the SCM query for the duration of the test.
func withServiceProcessID(t *testing.T, pid uint32, err error) {
	t.Helper()
	previous := queryServiceProcessID
	queryServiceProcessID = func(name string) (uint32, error) {
		if name != serviceName {
			t.Errorf("SCM queried for %q", name)
		}
		return pid, err
	}
	t.Cleanup(func() { queryServiceProcessID = previous })
}

// testServicePipe serves a private pipe with the service DACL for the current user.
func testServicePipe(t *testing.T, path, sid string) (*atomic.Int64, func()) {
	t.Helper()
	sddl, err := servicePipeSDDL(sid, sid)
	if err != nil {
		t.Fatal(err)
	}
	l, err := listenPipe(path, sddl+testInstanceACE(sid))
	if err != nil {
		t.Fatal(err)
	}
	return countingPipe(l)
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
	read, stop := testServicePipe(t, path, sid)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	self := uint32(os.Getpid())
	for _, test := range []struct {
		name  string
		owner string
		pid   uint32
		err   error
		ok    bool
	}{
		{"expected owner and process", sid, self, nil, true},
		{"pipe owned by another principal", serviceObjectOwner, self, nil, false},
		{"another service process", sid, self + 4, nil, false},
		{"service stopped or no process", sid, 0, nil, false},
		{"service not installed", sid, 0, windows.ERROR_SERVICE_DOES_NOT_EXIST, false},
		{"SCM access denied", sid, 0, windows.ERROR_ACCESS_DENIED, false},
	} {
		withServiceProcessID(t, test.pid, test.err)
		c, err := dialServicePipe(ctx, path, pipeTrust{serviceOwner: test.owner, service: serviceName})
		if test.ok {
			if err != nil {
				t.Errorf("%s: rejected: %v", test.name, err)
				continue
			}
			c.Close()
		} else if !errors.Is(err, ErrServerUntrusted) {
			t.Errorf("%s: accepted: %v", test.name, err)
		}
	}
	stop()
	if n := read.Load(); n != 0 {
		t.Fatalf("server received %d bytes before identity verification", n)
	}

	// No service pipe: the client reports absence, whatever SCM says.
	withServiceProcessID(t, 0, windows.ERROR_SERVICE_DOES_NOT_EXIST)
	if _, err := dialServicePipe(ctx, path+".missing", pipeTrust{serviceOwner: sid, service: serviceName}); !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		t.Fatal("missing service pipe:", err)
	}
}

const pipeInstanceHelperEnv = "BIMERON_TEST_PIPE_INSTANCE"

// TestPipeInstanceHelper serves one additional instance of an existing pipe in
// a child process. It does nothing unless started by startPipeInstance.
func TestPipeInstanceHelper(t *testing.T) {
	path := os.Getenv(pipeInstanceHelperEnv)
	if path == "" {
		t.Skip("helper process only")
	}
	ptr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateNamedPipe(ptr, windows.PIPE_ACCESS_DUPLEX, windows.PIPE_REJECT_REMOTE_CLIENTS, windows.PIPE_UNLIMITED_INSTANCES, 512, 512, 0, nil)
	if err != nil {
		fmt.Printf("instance-error %d\n", err)
		return
	}
	defer windows.CloseHandle(h)
	fmt.Println("instance-ready")
	if err := windows.ConnectNamedPipe(h, nil); err != nil && !errors.Is(err, windows.ERROR_PIPE_CONNECTED) {
		t.Fatal(err)
	}
	var total, n uint32
	b := make([]byte, 512)
	for windows.ReadFile(h, b, &n, nil) == nil && n > 0 {
		total += n
	}
	fmt.Printf("instance-read %d\n", total)
}

// startPipeInstance runs TestPipeInstanceHelper for path as the current user
// and returns its first status line and a function that waits for its last.
func startPipeInstance(t *testing.T, path string) (string, func() string) {
	t.Helper()
	helper := exec.Command(os.Args[0], "-test.run=^TestPipeInstanceHelper$", "-test.v")
	helper.Env = append(os.Environ(), pipeInstanceHelperEnv+"="+path)
	stdout, err := helper.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := helper.Start(); err != nil {
		t.Fatal(err)
	}
	lines := bufio.NewScanner(stdout)
	status := func() string {
		for lines.Scan() {
			if strings.HasPrefix(lines.Text(), "instance-") {
				return lines.Text()
			}
		}
		return ""
	}
	first := status()
	return first, func() string {
		last := status()
		if err := helper.Wait(); err != nil {
			t.Error("helper:", err)
		}
		return last
	}
}

// GetNamedPipeServerProcessId reports the process that created the pipe, also
// for instances that another process serves. Only the pipe DACL keeps other
// processes from serving instances, and SCM must report a running service.
func TestServicePipeAdditionalInstance(t *testing.T) {
	if os.Getenv(pipeInstanceHelperEnv) != "" {
		t.Skip("helper process")
	}
	_, sid, err := pipeIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if sid == serviceObjectOwner {
		t.Skip("test needs a non-SYSTEM owner")
	}
	sddl, err := servicePipeSDDL(sid, sid)
	if err != nil {
		t.Fatal(err)
	}

	// The owner user cannot add an instance to the service pipe from another process.
	path := fmt.Sprintf(`\\.\pipe\Bimeron.InstanceTest.%d`, time.Now().UnixNano())
	l, err := listenPipe(path, sddl)
	if err != nil {
		t.Fatal(err)
	}
	first, wait := startPipeInstance(t, path)
	if want := fmt.Sprintf("instance-error %d", windows.ERROR_ACCESS_DENIED); first != want {
		t.Errorf("owner user process: %q, want %q", first, want)
	}
	wait()
	l.Close()

	// An instance that outlives the process that created the pipe is rejected
	// because SCM reports no service process.
	path += ".outlived"
	l, err = listenPipe(path, sddl+testInstanceACE(sid))
	if err != nil {
		t.Fatal(err)
	}
	first, wait = startPipeInstance(t, path)
	if first != "instance-ready" {
		l.Close()
		t.Fatalf("helper: %q", first)
	}
	l.Close()
	withServiceProcessID(t, 0, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := dialServicePipe(ctx, path, pipeTrust{serviceOwner: sid, service: serviceName})
	if c != nil {
		c.Close()
	}
	if !errors.Is(err, ErrServerUntrusted) {
		t.Error("pipe instance without a service process accepted:", err)
	}
	if last := wait(); last != "instance-read 0" {
		t.Fatalf("helper reported %q", last)
	}
}

func TestDialPipesConsoleIdentity(t *testing.T) {
	path, sid, err := pipeIdentity()
	if err != nil {
		t.Fatal(err)
	}
	elevated := windows.GetCurrentProcessToken().IsElevated()
	stamp := time.Now().UnixNano()
	console := fmt.Sprintf("%s.console.%d", path, stamp)
	missing := fmt.Sprintf(`\\.\pipe\Bimeron.IdentityTest.Missing.%d`, stamp)
	sddl := consolePipeSDDL("BA", sid)
	if !elevated {
		// A non-elevated user can neither own the pipe as Administrators nor
		// create its instances. The test server needs both.
		sddl = consolePipeSDDL(sid, sid) + testInstanceACE(sid)
	}
	l, err := listenPipe(console, sddl)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- NewServer(&fakeEngine{state: core.Disconnected, events: make(chan core.Event)}).Serve(ctx, l)
	}()
	defer func() { cancel(); <-done }()
	withServiceProcessID(t, 0, windows.ERROR_SERVICE_DOES_NOT_EXIST)
	want := pipeTrust{serviceObjectOwner, serviceName, consoleObjectOwner, sid}
	status := func() error {
		c, err := dialPipes(ctx, missing, console, want)
		if err != nil {
			return err
		}
		defer c.Close()
		_, err = exchange(ctx, c, Request{Command: "status"})
		return err
	}
	if !elevated {
		if err := status(); !errors.Is(err, ErrServerUntrusted) {
			t.Fatal("non-elevated console server accepted:", err)
		}
	} else {
		// Repeated calls need further pipe instances created by the elevated server.
		for range 3 {
			if err := status(); err != nil {
				t.Fatal("elevated same-user console server rejected:", err)
			}
		}
		// A non-elevated client of the same user accepts the elevated server.
		impersonating(t, limitedToken(t, administrators), func() { err = status() })
		if err != nil {
			t.Fatal("non-elevated client rejected the elevated console server:", err)
		}
	}
	other := want
	other.user = foreignUser
	if _, err := dialPipes(ctx, missing, console, other); !errors.Is(err, ErrServerUntrusted) {
		t.Fatal("console server of another user accepted:", err)
	}

	// A rejected service endpoint must not fall back to a trusted console daemon.
	service := fmt.Sprintf(`\\.\pipe\Bimeron.IdentityTest.Service.%d`, stamp)
	read, stop := testServicePipe(t, service, sid)
	if _, err := dialPipes(ctx, service, console, want); !errors.Is(err, ErrServerUntrusted) {
		t.Fatal("untrusted service endpoint was not rejected:", err)
	}
	// Nor when the owner matches but SCM reports no service process.
	owned := want
	owned.serviceOwner = sid
	withServiceProcessID(t, 0, nil)
	if _, err := dialPipes(ctx, service, console, owned); !errors.Is(err, ErrServerUntrusted) {
		t.Fatal("service endpoint without SCM process was not rejected:", err)
	}
	stop()
	if n := read.Load(); n != 0 {
		t.Fatalf("service endpoint received %d bytes", n)
	}
}
