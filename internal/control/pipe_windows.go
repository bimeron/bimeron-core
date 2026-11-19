//go:build windows

package control

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"sync"
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

// pipeClientRights is FILE_GENERIC_READ|FILE_GENERIC_WRITE without
// FILE_CREATE_PIPE_INSTANCE (0x4). A client can connect, read, write and read
// the owner, but cannot create pipe instances or change the DACL or owner.
// pipeInstanceRight is FILE_CREATE_PIPE_INSTANCE alone. Every server instance
// after the first one needs it, together with read and write access.
const (
	pipeClientRights  = "0x12019b"
	pipeInstanceRight = "0x4"
)

func Listen() (net.Listener, error) {
	path, sid, err := pipeIdentity()
	if err != nil {
		return nil, err
	}
	return listenPipe(path, consolePipeSDDL("BA", sid))
}

// consolePipeSDDL allows only this Windows user and SYSTEM to connect. Pipe
// instances also require Administrators, so only an elevated process of the
// user can serve the pipe.
func consolePipeSDDL(objectOwner, sid string) string {
	return "O:" + objectOwner + "D:P(A;;GA;;;SY)(A;;" + pipeClientRights + ";;;" + sid + ")(A;;" + pipeInstanceRight + ";;;BA)"
}

// listenPipe rejects remote clients and creates the first pipe instance
// exclusively, so a second server cannot take over an existing name.
func listenPipe(path, sddl string) (net.Listener, error) {
	return winio.ListenPipe(path, &winio.PipeConfig{SecurityDescriptor: sddl, InputBufferSize: 16 * 1024, OutputBufferSize: 16 * 1024})
}

const ServicePipe = `\\.\pipe\Bimeron.Core.Service`

func ListenService(ownerSID string) (net.Listener, error) {
	sddl, err := servicePipeSDDL("SY", ownerSID)
	if err != nil {
		return nil, err
	}
	return listenPipe(ServicePipe, sddl)
}

// servicePipeSDDL lets only SYSTEM create pipe instances. The control owner
// can connect but cannot serve the pipe.
func servicePipeSDDL(objectOwner, ownerSID string) (string, error) {
	sid, err := windows.StringToSid(ownerSID)
	if err != nil {
		return "", err
	}
	// Use canonical SID rather than interpolating unchecked caller text into SDDL.
	return "O:" + objectOwner + "D:P(A;;GA;;;SY)(A;;" + pipeClientRights + ";;;" + sid.String() + ")", nil
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
	if owner, err := pipeOwner(conn); err != nil || owner != want.consoleOwner {
		conn.Close()
		return nil, ErrServerUntrusted
	}
	process, sid, elevated, err := pipeServerProcess(conn)
	if err != nil {
		conn.Close()
		return nil, ErrServerUntrusted
	}
	if !elevated || sid != want.user {
		windows.CloseHandle(process)
		conn.Close()
		return nil, ErrServerUntrusted
	}
	return &processConn{Conn: conn, process: process}, nil
}

// processConn retains the verified server process handle until the connection
// is closed, so the inspected process ID cannot be reused during the exchange.
type processConn struct {
	net.Conn
	process windows.Handle
	once    sync.Once
}

func (c *processConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { windows.CloseHandle(c.process) })
	return err
}

func DialService(ctx context.Context) (net.Conn, error) {
	return dialServicePipe(ctx, ServicePipe, pipeTrust{serviceOwner: serviceObjectOwner, service: serviceName})
}

// Standard users cannot open a LocalSystem token, so the service is identified
// by the pipe owner and the SCM-reported service process ID. Unlike the console
// daemon client, no process handle is kept: a LocalSystem process grants
// standard users no access, and none is needed because only SYSTEM can create
// instances of this pipe, so every instance is served by a SYSTEM process.
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

// queryServiceProcessID reports the SCM process ID of a service. Tests
// replace it.
var queryServiceProcessID = scmServiceProcessID

// A service that serves its pipe always has a nonzero SCM process ID. A
// missing or stopped service, a failed SCM query or another process ID rejects
// the endpoint.
func serviceProcessMatches(c net.Conn, name string) bool {
	pid, err := pipeServerPID(c)
	if err != nil {
		return false
	}
	expected, err := queryServiceProcessID(name)
	return err == nil && expected != 0 && pid == expected
}
func scmServiceProcessID(name string) (uint32, error) {
	ptr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	m, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return 0, err
	}
	defer windows.CloseServiceHandle(m)
	s, err := windows.OpenService(m, ptr, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return 0, err
	}
	defer windows.CloseServiceHandle(s)
	var status windows.SERVICE_STATUS_PROCESS
	var size uint32
	if err = windows.QueryServiceStatusEx(s, windows.SC_STATUS_PROCESS_INFO, (*byte)(unsafe.Pointer(&status)), uint32(unsafe.Sizeof(status)), &size); err != nil {
		return 0, err
	}
	return status.ProcessId, nil
}

// pipeServerProcess opens the pipe server process once and inspects its token
// through that handle. The process must still run after the inspection. The
// caller closes the returned handle after the last use of the connection.
func pipeServerProcess(c net.Conn) (windows.Handle, string, bool, error) {
	pid, err := pipeServerPID(c)
	if err != nil {
		return 0, "", false, err
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, pid)
	if err != nil {
		return 0, "", false, err
	}
	sid, elevated, err := processUser(h)
	if err == nil {
		state, waitErr := windows.WaitForSingleObject(h, 0)
		if waitErr != nil || state != uint32(windows.WAIT_TIMEOUT) {
			err = ErrServerUntrusted
		}
	}
	if err != nil {
		windows.CloseHandle(h)
		return 0, "", false, err
	}
	return h, sid, elevated, nil
}
func processUser(h windows.Handle) (string, bool, error) {
	var token windows.Token
	if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &token); err != nil {
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
	return listenServiceReadinessPipe(ServiceReadinessPipe, readinessPipeSDDL("SY"))
}

// readinessPipeSDDL lets only SYSTEM create pipe instances. Administrators can
// connect but cannot serve the pipe or change its security.
func readinessPipeSDDL(objectOwner string) string {
	return "O:" + objectOwner + "D:P(A;;GA;;;SY)(A;;" + pipeClientRights + ";;;BA)"
}
func listenServiceReadinessPipe(path, sddl string) (net.Listener, error) {
	return winio.ListenPipe(path, &winio.PipeConfig{SecurityDescriptor: sddl, InputBufferSize: 1024, OutputBufferSize: 4096})
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

// PipePeerProcess watches the client process of a named pipe connection. It
// returns nil when the client cannot be identified.
func PipePeerProcess(c net.Conn) ProcessWatch {
	fd, ok := c.(interface{ Fd() uintptr })
	if !ok {
		return nil
	}
	var pid uint32
	if windows.GetNamedPipeClientProcessId(windows.Handle(fd.Fd()), &pid) != nil || pid == 0 {
		return nil
	}
	h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, pid)
	if err != nil {
		return nil
	}
	return processHandle(h)
}

type processHandle windows.Handle

func (h processHandle) Alive() bool {
	status, err := windows.WaitForSingleObject(windows.Handle(h), 0)
	return err == nil && status == uint32(windows.WAIT_TIMEOUT)
}

func (h processHandle) Close() { windows.CloseHandle(windows.Handle(h)) }
