//go:build linux

package main

import (
	"bimeron/internal/unixutil"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

const developerRecordDirectory = "/run/bimeron-developer"

func developerRecordPath(owner string) string {
	return filepath.Join(developerRecordDirectory, owner+".json")
}
func developerRecordRead(owner string) ([]byte, error) {
	path := developerRecordPath(owner)
	if err := protectedRepairPath(path); err != nil {
		return nil, err
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	var b [8193]byte
	n, e := f.Read(b[:])
	if e != nil {
		return nil, e
	}
	return b[:n], nil
}
func developerRecordWrite(r developerRecord) error {
	if err := os.Mkdir(developerRecordDirectory, 0700); err != nil && !os.IsExist(err) {
		return err
	}
	if err := protectedRepairPath(developerRecordDirectory); err != nil {
		return err
	}
	data, e := json.Marshal(r)
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(developerRecordDirectory, "record-")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(data)
	}
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil {
		return e
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(f.Name(), developerRecordPath(r.Owner))
}
func inspectDeveloperProcess(pid uint32, owner string) (developerRecord, func(), func() bool, error) {
	r := developerRecord{Version: 1, PID: pid, Owner: owner}
	fd, e := unix.PidfdOpen(int(pid), 0)
	if e != nil {
		return r, nil, nil, e
	}
	release := func() { unix.Close(fd) }
	fail := func(err error) (developerRecord, func(), func() bool, error) { release(); return r, nil, nil, err }
	base := fmt.Sprintf("/proc/%d", pid)
	var info unix.Stat_t
	if e = unix.Stat(base, &info); e != nil || info.Uid != 0 {
		return fail(errors.New("developer process is not root"))
	}
	data, e := os.ReadFile(base + "/stat")
	if e != nil {
		return fail(e)
	}
	end := strings.LastIndexByte(string(data), ')')
	if end < 0 {
		return fail(errors.New("developer start time unavailable"))
	}
	fields := strings.Fields(string(data[end+1:]))
	if len(fields) < 20 {
		return fail(errors.New("developer stat invalid"))
	}
	boot, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if e != nil {
		return fail(e)
	}
	r.Created = strings.TrimSpace(string(boot)) + ":" + fields[19]
	r.Image, e = os.Readlink(base + "/exe")
	if e != nil {
		return fail(e)
	}
	image, e := os.Open(base + "/exe")
	if e != nil {
		return fail(e)
	}
	processRelease := release
	release = func() { image.Close(); processRelease() }
	pinned, e := image.Stat()
	if e != nil {
		return fail(e)
	}
	r.Image, e = os.Readlink(fmt.Sprintf("/proc/self/fd/%d", image.Fd()))
	if e != nil {
		return fail(e)
	}
	r.SHA256, e = developerDigest(fmt.Sprintf("/proc/self/fd/%d", image.Fd()))
	if e != nil {
		return fail(e)
	}
	exited := func() bool {
		p := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		n, e := unix.Poll(p, 0)
		return e != nil || n > 0 || !developerImageMatches(pinned, base+"/exe")
	}
	if exited() {
		return fail(errors.New("developer process exited"))
	}
	return r, release, exited, nil
}
func beginDeveloperRecord() (func(bool) error, error) {
	owner := os.Getenv("BIMERON_CONTROL_UID")
	if owner == "" {
		owner = os.Getenv("SUDO_UID")
	}
	if owner == "" {
		owner = "0"
	}
	uid, e := strconv.ParseUint(owner, 10, 32)
	if e != nil {
		return nil, e
	}
	owner = strconv.FormatUint(uid, 10)
	r, release, _, e := inspectDeveloperProcess(uint32(os.Getpid()), owner)
	if e != nil {
		return nil, e
	}
	defer release()
	if e = developerRecordWrite(r); e != nil {
		return nil, e
	}
	return func(clean bool) error {
		if !clean {
			return nil
		}
		r.Clean = true
		return developerRecordWrite(r)
	}, nil
}
func (b *linuxRepairBackend) DeveloperPending(ctx context.Context) (bool, error) {
	data, e := developerRecordRead(strconv.FormatUint(uint64(b.owner), 10))
	if os.IsNotExist(e) {
		return false, nil
	}
	if e != nil {
		return false, e
	}
	r, e := parseDeveloperRecord(data)
	if e != nil {
		return false, e
	}
	if r.Clean {
		if r.Owner != strconv.FormatUint(uint64(b.owner), 10) {
			return false, errors.New("developer owner mismatch")
		}
		fd, err := unix.PidfdOpen(int(r.PID), 0)
		if errors.Is(err, unix.ESRCH) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		defer unix.Close(fd)
		poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		n, err := unix.Poll(poll, 0)
		if err == nil && n > 0 && poll[0].Revents&unix.POLLIN != 0 {
			return false, nil
		}
		return false, errors.New("developer process exit not proven")
	}
	current, release, _, e := inspectDeveloperProcess(r.PID, r.Owner)
	if e != nil {
		return false, errors.New("developer process exit lacks cleanup evidence")
	}
	defer release()
	if r.Owner != strconv.FormatUint(uint64(b.owner), 10) || !sameDeveloper(r, current) {
		return false, errors.New("developer identity mismatch or PID reuse")
	}
	return true, nil
}
func (b *linuxRepairBackend) StopDeveloper(ctx context.Context) error {
	owner := strconv.FormatUint(uint64(b.owner), 10)
	data, e := developerRecordRead(owner)
	if e != nil {
		return e
	}
	r, e := parseDeveloperRecord(data)
	if e != nil {
		return e
	}
	current, release, exited, e := inspectDeveloperProcess(r.PID, owner)
	if e != nil {
		return e
	}
	defer release()
	if !sameDeveloper(r, current) || r.Clean {
		return errors.New("developer identity changed")
	}
	dial := func(ctx context.Context) (net.Conn, error) {
		c, e := (&net.Dialer{}).DialContext(ctx, "unix", filepath.Join(unixutil.RuntimeDir, "control.sock"))
		if e != nil {
			return nil, e
		}
		if !developerEndpointMatches(c, r.PID, 0) || exited() {
			c.Close()
			return nil, errors.New("developer endpoint identity rejected")
		}
		return c, nil
	}
	return stopRecordedDeveloper(ctx, r, dial, exited, func() ([]byte, error) { return developerRecordRead(owner) })
}

func developerEndpointMatches(c net.Conn, pid, uid uint32) bool {
	sc, ok := c.(syscall.Conn)
	if !ok {
		return false
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return false
	}
	var cred *unix.Ucred
	var query error
	err = raw.Control(func(fd uintptr) { cred, query = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) })
	return err == nil && query == nil && cred != nil && uint32(cred.Pid) == pid && cred.Uid == uid
}

func developerImageMatches(pinned os.FileInfo, path string) bool {
	live, err := os.Stat(path)
	return err == nil && os.SameFile(pinned, live)
}
