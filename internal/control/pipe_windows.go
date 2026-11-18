//go:build windows

package control

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

func pipeIdentity() (string, string, error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", "", err
	}
	sid := u.User.Sid.String()
	digest := sha256.Sum256([]byte(sid))
	return fmt.Sprintf(`\\.\pipe\Bimeron.Core.%x`, digest[:16]), sid, nil
}

// Pipe object owners. Clients verify them before writing; other principals
// cannot assign SYSTEM or Administrators as owner.
const (
	serviceObjectOwner = "S-1-5-18"
	consoleObjectOwner = "S-1-5-32-544"
	serviceName        = "BimeronCore"
)

func Listen() (net.Listener, error) {
	path, sid, err := pipeIdentity()
	if err != nil {
		return nil, err
	}
	return listenConsolePipe(path, "BA", sid)
}
func listenConsolePipe(path, objectOwner, sid string) (net.Listener, error) {
	// Protected DACL, only this Windows user and SYSTEM. go-winio rejects remote
	// clients and creates the first pipe instance exclusively (no second daemon).
	return winio.ListenPipe(path, &winio.PipeConfig{SecurityDescriptor: "O:" + objectOwner + "D:P(A;;GA;;;SY)(A;;GA;;;" + sid + ")", InputBufferSize: 16 * 1024, OutputBufferSize: 16 * 1024})
}

const ServicePipe = `\\.\pipe\Bimeron.Core.Service`

func ListenService(ownerSID string) (net.Listener, error) {
	return listenServicePipe(ServicePipe, "SY", ownerSID)
}
func listenServicePipe(path, objectOwner, ownerSID string) (net.Listener, error) {
	dacl, err := servicePipeDACL(ownerSID)
	if err != nil {
		return nil, err
	}
	return winio.ListenPipe(path, &winio.PipeConfig{SecurityDescriptor: "O:" + objectOwner + dacl, InputBufferSize: 16 * 1024, OutputBufferSize: 16 * 1024})
}
func servicePipeDACL(ownerSID string) (string, error) {
	sid, err := windows.StringToSid(ownerSID)
	if err != nil {
		return "", err
	}
	// Use canonical SID rather than interpolating unchecked caller text into SDDL.
	return "D:P(A;;GA;;;SY)(A;;GA;;;" + sid.String() + ")", nil
}

// pipeTrust is the server identity a client requires before writing.
type pipeTrust struct {
	serviceOwner, service, consoleOwner, user string
}

func Dial(ctx context.Context) (net.Conn, error) {
	path, sid, err := pipeIdentity()
	if err != nil {
		return nil, err
	}
	return dialPipes(ctx, ServicePipe, path, pipeTrust{serviceObjectOwner, serviceName, consoleObjectOwner, sid})
}

// dialPipes prefers a running service and falls back to the console daemon
// only when the service pipe does not exist, never after a rejected identity.
func dialPipes(ctx context.Context, service, console string, want pipeTrust) (net.Conn, error) {
	conn, err := dialServicePipe(ctx, service, want)
	if err == nil || !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return conn, err
	}
	conn, err = winio.DialPipeContext(ctx, console)
	if err != nil {
		return nil, err
	}
	owner, ownerErr := pipeOwner(conn)
	sid, elevated, userErr := pipeServerUser(conn)
	if ownerErr != nil || userErr != nil || owner != want.consoleOwner || !elevated || sid != want.user {
		conn.Close()
		return nil, ErrServerUntrusted
	}
	return conn, nil
}
func DialService(ctx context.Context) (net.Conn, error) {
	return dialServicePipe(ctx, ServicePipe, pipeTrust{serviceOwner: serviceObjectOwner, service: serviceName})
}

// Standard users cannot open a LocalSystem token, so the service is identified
// by the pipe owner and, when SCM reports one, the service process ID.
func dialServicePipe(ctx context.Context, path string, want pipeTrust) (net.Conn, error) {
	conn, err := winio.DialPipeContext(ctx, path)
	if err != nil {
		return nil, err
	}
	owner, err := pipeOwner(conn)
	if err != nil || owner != want.serviceOwner || !serviceProcessMatches(conn, want.service) {
		conn.Close()
		return nil, ErrServerUntrusted
	}
	return conn, nil
}
func pipeOwner(c net.Conn) (string, error) {
	fd, ok := c.(interface{ Fd() uintptr })
	if !ok {
		return "", ErrServerUntrusted
	}
	sd, err := windows.GetSecurityInfo(windows.Handle(fd.Fd()), windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return "", err
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return "", ErrServerUntrusted
	}
	return owner.String(), nil
}
func pipeServerPID(c net.Conn) (uint32, error) {
	fd, ok := c.(interface{ Fd() uintptr })
	var pid uint32
	if !ok || windows.GetNamedPipeServerProcessId(windows.Handle(fd.Fd()), &pid) != nil || pid == 0 {
		return 0, ErrServerUntrusted
	}
	return pid, nil
}

// An empty name, a missing service or no reported process skips the binding.
func serviceProcessMatches(c net.Conn, name string) bool {
	if name == "" {
		return true
	}
	pid, err := pipeServerPID(c)
	expected := serviceProcessID(name)
	return err == nil && (expected == 0 || pid == expected)
}
func serviceProcessID(name string) uint32 {
	ptr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0
	}
	m, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return 0
	}
	defer windows.CloseServiceHandle(m)
	s, err := windows.OpenService(m, ptr, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return 0
	}
	defer windows.CloseServiceHandle(s)
	var status windows.SERVICE_STATUS_PROCESS
	var size uint32
	if windows.QueryServiceStatusEx(s, windows.SC_STATUS_PROCESS_INFO, (*byte)(unsafe.Pointer(&status)), uint32(unsafe.Sizeof(status)), &size) != nil {
		return 0
	}
	return status.ProcessId
}
func pipeServerUser(c net.Conn) (string, bool, error) {
	pid, err := pipeServerPID(c)
	if err != nil {
		return "", false, err
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", false, err
	}
	defer windows.CloseHandle(h)
	var token windows.Token
	if err = windows.OpenProcessToken(h, windows.TOKEN_QUERY, &token); err != nil {
		return "", false, err
	}
	defer token.Close()
	u, err := token.GetTokenUser()
	if err != nil {
		return "", false, err
	}
	return u.User.Sid.String(), token.IsElevated(), nil
}

const ServiceReadinessPipe = `\\.\pipe\Bimeron.Core.Readiness`

func ListenServiceReadiness() (net.Listener, error) {
	return listenServiceReadinessPipe(ServiceReadinessPipe, "SY")
}
func listenServiceReadinessPipe(path, objectOwner string) (net.Listener, error) {
	return winio.ListenPipe(path, &winio.PipeConfig{SecurityDescriptor: "O:" + objectOwner + "D:P(A;;GA;;;SY)(A;;GA;;;BA)", InputBufferSize: 1024, OutputBufferSize: 4096})
}

// CallServiceReadiness binds the responding process to the SCM-observed service.
func CallServiceReadiness(ctx context.Context, pid uint32, r Request) (Response, error) {
	return callServiceReadinessPipe(ctx, ServiceReadinessPipe, pid, r)
}
func callServiceReadinessPipe(ctx context.Context, path string, pid uint32, r Request) (Response, error) {
	c, err := winio.DialPipeContext(ctx, path)
	if err != nil {
		return Response{}, err
	}
	defer c.Close()
	fd, ok := c.(interface{ Fd() uintptr })
	var actual uint32
	if !ok || pid == 0 || windows.GetNamedPipeServerProcessId(windows.Handle(fd.Fd()), &actual) != nil || actual != pid {
		return Response{}, fmt.Errorf("readiness service identity rejected")
	}
	return exchange(ctx, c, r)
}
