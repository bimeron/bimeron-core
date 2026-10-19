//go:build linux

package linuxnet

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"bimeron/internal/unixutil"
	"sort"
	"strings"
	"syscall"
	"time"
)

const RuntimeDir = unixutil.RuntimeDir

var ErrNetworkUnavailable = errors.New("network_unavailable")
var ErrTunnelLost = errors.New("tunnel_adapter_lost")

func EnsureRuntimeDir() error {
	return unixutil.EnsureRuntimeDir()
}

// Locks are never unlinked: deleting a locked inode would allow a second owner.
func Lock(name string) (func(), error) {
	return unixutil.Lock(name)
}
func lockFile(path string) (func(), error) {
	return unixutil.LockFile(path)
}
func NewManager() *Manager {
	return &Manager{Dir: RuntimeDir, Resolver: "/etc/resolv.conf", Run: runCommand}
}

func executable(name string) (string, error) {
	for _, dir := range []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin"} {
		path := filepath.Join(dir, name)
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0 {
			return path, nil
		}
	}
	return "", fmt.Errorf("required tool missing: %s", name)
}

type boundedBuffer struct{ bytes.Buffer }

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 1024*1024 {
		return 0, fmt.Errorf("command output limit")
	}
	return b.Buffer.Write(p)
}
func runCommand(ctx context.Context, name, input string, args ...string) ([]byte, error) {
	path, err := executable(name)
	if err != nil {
		return nil, err
	}
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(bounded, path, args...)
	cmd.Stdin = strings.NewReader(input)
	cmd.Env = append(os.Environ(), "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C")
	var out, diagnostics boundedBuffer
	cmd.Stdout = &out
	cmd.Stderr = &diagnostics
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s command failed", name)
	}
	return out.Bytes(), nil
}
func Requirements(guard bool) error {
	if err := EnsureRuntimeDir(); err != nil {
		return err
	}
	if _, err := executable("ip"); err != nil {
		return err
	}
	if guard {
		if _, err := executable("nft"); err != nil {
			return err
		}
	}
	info, err := os.Stat("/dev/net/tun")
	if err != nil || info.Mode()&os.ModeCharDevice == 0 {
		return fmt.Errorf("/dev/net/tun unavailable")
	}
	return nil
}

type Observation struct {
	Device    string
	Gateway   string
	Addresses []string
	DNS       []string
}

func (m *Manager) Observe(ctx context.Context, name string, startup bool) (Observation, error) {
	if startup {
		if err := m.Preflight(ctx, name); err != nil {
			return Observation{}, err
		}
	} else {
		iface, err := net.InterfaceByName(name)
		if err != nil || iface.Flags&net.FlagUp == 0 {
			return Observation{}, ErrTunnelLost
		}
	}
	routes, err := m.routes(ctx, "-4")
	if err != nil {
		return Observation{}, ErrNetworkUnavailable
	}
	var selected *route
	for i := range routes {
		r := &routes[i]
		table := scalar(r.Table)
		if (table == "main" || table == "254" || table == "") && r.Destination == "default" && r.Device != name {
			iface, e := net.InterfaceByName(r.Device)
			if e != nil || iface.Flags&net.FlagUp == 0 {
				continue
			}
			if selected == nil || r.Metric < selected.Metric {
				selected = r
			}
		}
	}
	if selected == nil {
		return Observation{}, ErrNetworkUnavailable
	}
	iface, err := net.InterfaceByName(selected.Device)
	if err != nil {
		return Observation{}, ErrNetworkUnavailable
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return Observation{}, ErrNetworkUnavailable
	}
	result := Observation{Device: selected.Device, Gateway: selected.Gateway, DNS: m.BootstrapDNS(ctx, selected.Device)}
	for _, a := range addrs {
		result.Addresses = append(result.Addresses, a.String())
	}
	sort.Strings(result.Addresses)
	return result, nil
}

func BoundDialer(device string) func(string, string, syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var result error
		err := c.Control(func(fd uintptr) {
			result = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, Mark)
			if result == nil {
				result = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, device)
			}
		})
		if err != nil {
			return err
		}
		return result
	}
}
