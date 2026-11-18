//go:build linux || darwin

package control

import (
	"bimeron/internal/unixutil"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
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
	if err := verifySocketPath(unixutil.RuntimeDir, socketPath, 0); err != nil {
		return nil, err
	}
	c, err := (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
	if err != nil {
		return nil, err
	}
	if err = trustedServer(peerUID(c.(*net.UnixConn))); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

// verifySocketPath rejects a runtime directory that root does not own or that
// others can write, and a socket path that is not a socket. The peer
// credential check after connecting remains authoritative.
func verifySocketPath(dir, path string, root uint32) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || stat.Uid != root || info.Mode().Perm()&0022 != 0 {
		return ErrServerUntrusted
	}
	if info, err = os.Lstat(path); err != nil {
		return err
	}
	if info.Mode().Type() != os.ModeSocket {
		return ErrServerUntrusted
	}
	return nil
}

// The service and the console daemon both run as root.
func trustedServer(uid uint32, err error) error {
	if err != nil || uid != 0 {
		return ErrServerUntrusted
	}
	return nil
}
func DialService(ctx context.Context) (net.Conn, error) { return Dial(ctx) }
