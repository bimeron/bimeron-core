//go:build windows

package control

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"

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
func Listen() (net.Listener, error) {
	path, sid, err := pipeIdentity()
	if err != nil {
		return nil, err
	}
	// Protected DACL, only this Windows user and SYSTEM. go-winio rejects remote
	// clients and creates the first pipe instance exclusively (no second daemon).
	return winio.ListenPipe(path, &winio.PipeConfig{SecurityDescriptor: "D:P(A;;GA;;;SY)(A;;GA;;;" + sid + ")", InputBufferSize: 16 * 1024, OutputBufferSize: 16 * 1024})
}

const ServicePipe = `\\.\pipe\Bimeron.Core.Service`

func ListenService(ownerSID string) (net.Listener, error) {
	return listenServicePipe(ServicePipe, ownerSID)
}
func listenServicePipe(path, ownerSID string) (net.Listener, error) {
	dacl, err := servicePipeDACL(ownerSID)
	if err != nil {
		return nil, err
	}
	return winio.ListenPipe(path, &winio.PipeConfig{SecurityDescriptor: dacl, InputBufferSize: 16 * 1024, OutputBufferSize: 16 * 1024})
}
func servicePipeDACL(ownerSID string) (string, error) {
	sid, err := windows.StringToSid(ownerSID)
	if err != nil {
		return "", err
	}
	// Use canonical SID rather than interpolating unchecked caller text into SDDL.
	return "D:P(A;;GA;;;SY)(A;;GA;;;" + sid.String() + ")", nil
}
func Dial(ctx context.Context) (net.Conn, error) {
	path, _, err := pipeIdentity()
	if err != nil {
		return nil, err
	}
	// A running service is preferred; absent service keeps console daemon support.
	conn, err := winio.DialPipeContext(ctx, ServicePipe)
	if err == nil {
		return conn, nil
	}
	if !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return nil, err
	}
	return winio.DialPipeContext(ctx, path)
}
func DialService(ctx context.Context) (net.Conn, error) {
	return winio.DialPipeContext(ctx, ServicePipe)
}

const ServiceReadinessPipe = `\\.\pipe\Bimeron.Core.Readiness`

func ListenServiceReadiness() (net.Listener, error) {
	return listenServiceReadinessPipe(ServiceReadinessPipe)
}
func listenServiceReadinessPipe(path string) (net.Listener, error) {
	return winio.ListenPipe(path, &winio.PipeConfig{SecurityDescriptor: "D:P(A;;GA;;;SY)(A;;GA;;;BA)", InputBufferSize: 1024, OutputBufferSize: 4096})
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
