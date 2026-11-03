//go:build windows

package main

import (
	"bimeron/internal/control"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"
	"unsafe"
)

func developerRecordLocation(owner string) (string, string, error) {
	root, e := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if e != nil {
		return "", "", e
	}
	dir := filepath.Join(root, "Bimeron Developer")
	sum := sha256.Sum256([]byte(owner))
	return dir, filepath.Join(dir, fmt.Sprintf("%x.json", sum[:16])), nil
}
func developerRecordRead(owner string) ([]byte, error) {
	dir, path, e := developerRecordLocation(owner)
	if e != nil {
		return nil, e
	}
	release, e := control.LockRepairDirectory(dir)
	if e != nil {
		return nil, e
	}
	defer release()
	releaseImage, e := control.LockRepairImage(path)
	if e != nil {
		return nil, e
	}
	defer releaseImage()
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, 8193))
}
func developerRecordWrite(r developerRecord) error {
	dir, path, e := developerRecordLocation(r.Owner)
	if e != nil {
		return e
	}
	root := filepath.Dir(dir)
	releaseRoot, e := control.LockRepairDirectory(root)
	if e != nil {
		return e
	}
	defer releaseRoot()
	sd, e := windows.SecurityDescriptorFromString("O:BAG:BAD:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)")
	if e != nil {
		return e
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	ptr, e := windows.UTF16PtrFromString(dir)
	if e != nil {
		return e
	}
	if e = windows.CreateDirectory(ptr, &sa); e != nil && e != windows.ERROR_ALREADY_EXISTS {
		return e
	}
	release, e := control.LockRepairDirectory(dir)
	if e != nil {
		return e
	}
	defer release()
	temp := path + "." + strconv.Itoa(os.Getpid()) + ".tmp"
	p, e := windows.UTF16PtrFromString(temp)
	if e != nil {
		return e
	}
	h, e := windows.CreateFile(p, windows.GENERIC_WRITE, 0, &sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if e != nil {
		return e
	}
	f := os.NewFile(uintptr(h), temp)
	defer os.Remove(temp)
	data, e := json.Marshal(r)
	if e == nil {
		_, e = f.Write(data)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	dest, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return e
	}
	return windows.MoveFileEx(p, dest, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}
func inspectDeveloperProcess(pid uint32, owner string) (developerRecord, func(), func() bool, error) {
	r := developerRecord{Version: 1, PID: pid}
	h, e := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, pid)
	if e != nil {
		return r, nil, nil, e
	}
	release := func() { windows.CloseHandle(h) }
	fail := func(err error) (developerRecord, func(), func() bool, error) { release(); return r, nil, nil, err }
	var created, exit, kernel, user windows.Filetime
	if e = windows.GetProcessTimes(h, &created, &exit, &kernel, &user); e != nil {
		return fail(e)
	}
	r.Created = strconv.FormatUint(uint64(created.HighDateTime)<<32|uint64(created.LowDateTime), 10)
	var token windows.Token
	if e = windows.OpenProcessToken(h, windows.TOKEN_QUERY, &token); e != nil {
		return fail(e)
	}
	defer token.Close()
	u, e := token.GetTokenUser()
	if e != nil {
		return fail(e)
	}
	r.Owner = u.User.Sid.String()
	if !token.IsElevated() || (owner != "" && r.Owner != owner) {
		return fail(errors.New("developer owner rejected"))
	}
	if e = windows.ProcessIdToSessionId(pid, &r.Session); e != nil || r.Session == 0 {
		return fail(errors.New("developer session rejected"))
	}
	path := make([]uint16, 32768)
	size := uint32(len(path))
	if e = windows.QueryFullProcessImageName(h, 0, &path[0], &size); e != nil {
		return fail(e)
	}
	r.Image = windows.UTF16ToString(path[:size])
	imageRelease, e := control.LockRepairImage(r.Image)
	if e != nil {
		return fail(errors.New("developer image cannot be securely pinned"))
	}
	processRelease := release
	release = func() { imageRelease(); processRelease() }
	r.SHA256, e = developerDigest(r.Image)
	if e != nil {
		return fail(e)
	}
	exited := func() bool {
		state, e := windows.WaitForSingleObject(h, 0)
		return e == nil && state == windows.WAIT_OBJECT_0
	}
	if exited() {
		return fail(errors.New("developer process exited"))
	}
	return r, release, exited, nil
}
func beginDeveloperRecord() (func(bool) error, error) {
	r, release, _, e := inspectDeveloperProcess(uint32(os.Getpid()), "")
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
func (b *windowsRepairBackend) DeveloperPending(ctx context.Context) (bool, error) {
	data, e := developerRecordRead(b.owner)
	if os.IsNotExist(e) || errors.Is(e, windows.ERROR_PATH_NOT_FOUND) || errors.Is(e, windows.ERROR_FILE_NOT_FOUND) {
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
		if r.Owner != b.owner || r.Session != b.session {
			return false, errors.New("developer owner/session mismatch")
		}
		h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, r.PID)
		if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		defer windows.CloseHandle(h)
		state, err := windows.WaitForSingleObject(h, 0)
		if err == nil && state == windows.WAIT_OBJECT_0 {
			return false, nil
		}
		return false, errors.New("developer process exit not proven")
	}
	current, release, _, e := inspectDeveloperProcess(r.PID, b.owner)
	if e != nil {
		return false, errors.New("developer process exit lacks cleanup evidence")
	}
	defer release()
	if !sameDeveloper(r, current) || r.Session != b.session {
		return false, errors.New("developer identity mismatch or PID reuse")
	}
	return true, nil
}
func (b *windowsRepairBackend) StopDeveloper(ctx context.Context) error {
	data, e := developerRecordRead(b.owner)
	if e != nil {
		return e
	}
	r, e := parseDeveloperRecord(data)
	if e != nil {
		return e
	}
	current, release, exited, e := inspectDeveloperProcess(r.PID, b.owner)
	if e != nil {
		return e
	}
	defer release()
	if !sameDeveloper(r, current) || r.Session != b.session || r.Clean {
		return errors.New("developer identity changed")
	}
	sum := sha256.Sum256([]byte(b.owner))
	path := fmt.Sprintf(`\\.\pipe\Bimeron.Core.%x`, sum[:16])
	dial := func(ctx context.Context) (net.Conn, error) {
		probe, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		c, e := winio.DialPipeContext(probe, path)
		if e != nil {
			return nil, e
		}
		if !developerEndpointMatches(c, r.PID) || exited() {
			c.Close()
			return nil, errors.New("developer endpoint identity rejected")
		}
		return c, nil
	}
	return stopRecordedDeveloper(ctx, r, dial, exited, func() ([]byte, error) { return developerRecordRead(b.owner) })
}

func developerEndpointMatches(c net.Conn, expected uint32) bool {
	fd, ok := c.(interface{ Fd() uintptr })
	var pid uint32
	return ok && windows.GetNamedPipeServerProcessId(windows.Handle(fd.Fd()), &pid) == nil && pid == expected
}
