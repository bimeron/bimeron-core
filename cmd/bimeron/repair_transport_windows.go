//go:build windows

package main

import (
	"errors"
	"fmt"
	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
	"net"
)

// repairClientRights is FILE_GENERIC_READ|FILE_GENERIC_WRITE without
// FILE_CREATE_PIPE_INSTANCE, WRITE_DAC or WRITE_OWNER: the caller can connect,
// read and write, but cannot serve the pipe or change its security.
const repairClientRights = "0x12019b"

// repairPipeSDDL gives SYSTEM and Administrators, which the elevated broker
// holds, full control and the calling user client rights only. The explicit
// owner keeps the caller from gaining owner rights when the default owner of
// the broker's token is the user.
func repairPipeSDDL(objectOwner, callerSID string) string {
	return "O:" + objectOwner + "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;" + repairClientRights + ";;;" + callerSID + ")"
}

func listenRepairSession(nonce string, pid uint32) (net.Listener, repairPeerCheck, func(), error) {
	return listenRepairPipe(nonce, pid, func(caller string) string { return repairPipeSDDL("BA", caller) })
}

// listenRepairPipe takes the pipe security descriptor for the caller's SID, so
// tests that run without elevation can serve the pipe.
func listenRepairPipe(nonce string, pid uint32, sddl func(callerSID string) string) (net.Listener, repairPeerCheck, func(), error) {
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, pid)
	if err != nil {
		return nil, nil, nil, err
	}
	release := func() { windows.CloseHandle(process) }
	var session uint32
	if err = windows.ProcessIdToSessionId(pid, &session); err != nil || session == 0 {
		release()
		return nil, nil, nil, errors.New("repair caller session rejected")
	}
	var token windows.Token
	if err = windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token); err != nil {
		release()
		return nil, nil, nil, err
	}
	user, err := token.GetTokenUser()
	token.Close()
	if err != nil {
		release()
		return nil, nil, nil, err
	}
	listener, err := winio.ListenPipe(`\\.\pipe\Bimeron.Repair.`+nonce, &winio.PipeConfig{SecurityDescriptor: sddl(user.User.Sid.String()), InputBufferSize: 1024, OutputBufferSize: 4096})
	if err != nil {
		release()
		return nil, nil, nil, err
	}
	authenticate := func(conn net.Conn) (string, error) {
		fd, ok := conn.(interface{ Fd() uintptr })
		if !ok {
			return "", errors.New("repair peer unavailable")
		}
		var actual uint32
		if windows.GetNamedPipeClientProcessId(windows.Handle(fd.Fd()), &actual) != nil || actual != pid {
			return "", errors.New("repair peer rejected")
		}
		var actualSession uint32
		if windows.ProcessIdToSessionId(actual, &actualSession) != nil || actualSession != session {
			return "", errors.New("repair peer session rejected")
		}
		state, err := windows.WaitForSingleObject(process, 0)
		if err != nil || state != uint32(windows.WAIT_TIMEOUT) {
			return "", errors.New("repair caller exited")
		}
		return fmt.Sprintf("%s|%d", user.User.Sid.String(), session), nil
	}
	return listener, authenticate, release, nil
}
