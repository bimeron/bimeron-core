//go:build darwin

package macnet

import (
	"bytes"
	"context"
	"fmt"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"os/exec"
	"bimeron/internal/unixutil"
	"sort"
	"strings"
	"syscall"
	"time"
)

var tools = map[string]string{"route": "/sbin/route", "ifconfig": "/sbin/ifconfig", "netstat": "/usr/sbin/netstat", "scutil": "/usr/sbin/scutil", "networksetup": "/usr/sbin/networksetup", "killall": "/usr/bin/killall"}

const StateDir = "/var/db/bimeron"

func Requirements() error {
	if err := unixutil.EnsureRuntimeDir(); err != nil {
		return err
	}
	if err := unixutil.EnsureRootDir(StateDir, 0700); err != nil {
		return err
	}
	for _, path := range tools {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm()&0111 == 0 {
			return fmt.Errorf("required macOS network tool missing")
		}
	}
	return nil
}
func NewManager() *Manager {
	return &Manager{Dir: StateDir, Run: runCommand, BootID: func() (string, error) {
		id, err := unix.Sysctl("kern.bootsessionuuid")
		if err != nil || !validServiceID(id) {
			return "", fmt.Errorf("cannot inspect macOS boot session")
		}
		return id, nil
	}, Index: func(name string) (int, error) {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			return 0, err
		}
		return iface.Index, nil
	}}
}

type boundedBuffer struct{ bytes.Buffer }

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 1024*1024 {
		return 0, fmt.Errorf("command output limit")
	}
	return b.Buffer.Write(p)
}
func runCommand(ctx context.Context, name, input string, args ...string) ([]byte, error) {
	path, ok := tools[name]
	if !ok {
		return nil, fmt.Errorf("unknown macOS network tool")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Stdin = strings.NewReader(input)
	cmd.Env = append(os.Environ(), "PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL=C", "LANG=C")
	var out, diagnostics boundedBuffer
	cmd.Stdout = &out
	cmd.Stderr = &diagnostics
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s command failed", name)
	}
	return out.Bytes(), nil
}

type Observation struct {
	Device, Gateway string
	Index           int
	Addresses, DNS  []string
}

func (m *Manager) Observe(ctx context.Context) (Observation, error) {
	device, gateway, err := m.Default(ctx)
	if err != nil {
		return Observation{}, err
	}
	iface, err := net.InterfaceByName(device)
	if err != nil || iface.Flags&net.FlagUp == 0 {
		return Observation{}, ErrNetworkUnavailable
	}
	addresses, err := iface.Addrs()
	if err != nil {
		return Observation{}, ErrNetworkUnavailable
	}
	result := Observation{Device: device, Gateway: gateway, Index: iface.Index, DNS: m.BootstrapDNS(ctx, device)}
	for _, a := range addresses {
		result.Addresses = append(result.Addresses, a.String())
	}
	sort.Strings(result.Addresses)
	return result, nil
}
func BoundDialer(index int) func(string, string, syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		level, option := unix.IPPROTO_IP, unix.IP_BOUND_IF
		if strings.HasSuffix(network, "6") {
			level, option = unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF
		}
		var result error
		err := c.Control(func(fd uintptr) { result = unix.SetsockoptInt(int(fd), level, option, index) })
		if err != nil {
			return err
		}
		return result
	}
}
