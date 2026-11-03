//go:build linux

package main

import (
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"syscall"
)

func listenRepairSession(nonce string, pid uint32) (net.Listener, repairPeerCheck, func(), error) {
	if os.Geteuid() != 0 {
		return nil, nil, nil, errors.New("repair requires root")
	}
	process, err := unix.PidfdOpen(int(pid), 0)
	if err != nil {
		return nil, nil, nil, err
	}
	release := func() { unix.Close(process) }
	var caller unix.Stat_t
	if err = unix.Stat(fmt.Sprintf("/proc/%d", pid), &caller); err != nil {
		release()
		return nil, nil, nil, err
	}
	const directory = "/run/bimeron-repair"
	if err = os.Mkdir(directory, 0755); err != nil && !os.IsExist(err) {
		release()
		return nil, nil, nil, err
	}
	var dir unix.Stat_t
	if unix.Lstat(directory, &dir) != nil || dir.Uid != 0 || dir.Mode&unix.S_IFMT != unix.S_IFDIR || dir.Mode&0022 != 0 {
		release()
		return nil, nil, nil, errors.New("untrusted repair directory")
	}
	path := directory + "/" + nonce + ".sock"
	// Never remove an existing endpoint: a collision fails closed.
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		release()
		return nil, nil, nil, err
	}
	if err = os.Chmod(path, 0600); err == nil {
		err = os.Chown(path, int(caller.Uid), int(caller.Gid))
	}
	if err != nil {
		listener.Close()
		release()
		return nil, nil, nil, err
	}
	authenticate := func(conn net.Conn) (string, error) {
		socket, ok := conn.(syscall.Conn)
		if !ok {
			return "", errors.New("repair peer unavailable")
		}
		raw, err := socket.SyscallConn()
		if err != nil {
			return "", err
		}
		var cred *unix.Ucred
		var query error
		err = raw.Control(func(fd uintptr) { cred, query = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) })
		if err != nil || query != nil || cred == nil || uint32(cred.Pid) != pid || cred.Uid != caller.Uid {
			return "", errors.New("repair peer rejected")
		}
		polls := []unix.PollFd{{Fd: int32(process), Events: unix.POLLIN}}
		n, err := unix.Poll(polls, 0)
		if err != nil || n != 0 {
			return "", errors.New("repair caller exited")
		}
		return fmt.Sprint(caller.Uid), nil
	}
	return listener, authenticate, release, nil
}
