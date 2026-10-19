//go:build linux || darwin

package control

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"bimeron/internal/unixutil"
	"strconv"
	"sync"
)

const socketPath = unixutil.RuntimeDir + "/control.sock"

type unixListener struct {
	*net.UnixListener
	release   func()
	uid       uint32
	path      string
	closeOnce sync.Once
	closeErr  error
}

func (l *unixListener) Accept() (net.Conn, error) {
	for {
		c, err := l.AcceptUnix()
		if err != nil {
			return nil, err
		}
		uid, err := peerUID(c)
		if err == nil && (uid == 0 || uid == l.uid) {
			return c, nil
		}
		c.Close()
	}
}
func (l *unixListener) Close() error {
	l.closeOnce.Do(func() {
		l.closeErr = l.UnixListener.Close()
		_ = os.Remove(l.path)
		l.release()
	})
	return l.closeErr
}
func Listen() (net.Listener, error) {
	release, err := unixutil.Lock("daemon.lock")
	if err != nil {
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			release()
		}
	}()
	uid, err := controlOwnerUID()
	if err != nil {
		return nil, err
	}
	l, err := listenUnix(unixutil.RuntimeDir, socketPath, uid, release)
	if err != nil {
		return nil, err
	}
	success = true
	return l, nil
}

func controlOwnerUID() (uint32, error) {
	value := os.Getenv("BIMERON_CONTROL_UID")
	if value == "" {
		value = os.Getenv("SUDO_UID")
	}
	if value != "" {
		n, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return 0, fmt.Errorf("invalid control owner UID")
		}
		return uint32(n), nil
	}
	return 0, nil
}

func listenUnix(runtimeDir, path string, uid uint32, release func()) (net.Listener, error) {
	success := false
	dir, err := os.MkdirTemp(runtimeDir, "socket-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	temp := filepath.Join(dir, "control.sock")
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: temp, Net: "unix"})
	if err != nil {
		return nil, err
	}
	l.SetUnlinkOnClose(false)
	defer func() {
		if !success {
			l.Close()
		}
	}()
	if err = os.Chmod(temp, 0600); err != nil {
		return nil, err
	}
	if err = os.Chown(temp, int(uid), os.Getegid()); err != nil {
		return nil, err
	}
	if err = os.Rename(temp, path); err != nil {
		return nil, err
	}
	success = true
	return &unixListener{UnixListener: l, release: release, uid: uid, path: path}, nil
}
func Dial(ctx context.Context) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
}
