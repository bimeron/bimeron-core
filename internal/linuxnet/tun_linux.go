//go:build linux

package linuxnet

import (
	"fmt"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"sync"
)

type TUN struct {
	stack.LinkEndpoint
	name string
	fd   int
	once sync.Once
}

func OpenTUN(name string, mtu uint32) (*TUN, error) {
	if !ValidName(name) {
		return nil, fmt.Errorf("invalid Linux TUN name")
	}
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			detachQueue(fd, name)
			unix.Close(fd)
		}
	}()
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return nil, err
	}
	// Exclusive creation closes the race between preflight and adapter creation.
	// The device is nonpersistent and vanishes when the last fd is closed.
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_TUN_EXCL)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		return nil, err
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		return nil, err
	}
	ep, err := fdbased.New(&fdbased.Options{FDs: []int{fd}, MTU: mtu, EthernetHeader: false, PacketDispatchMode: fdbased.Readv, MaxSyscallHeaderBytes: 0})
	if err != nil {
		return nil, err
	}
	success = true
	return &TUN{LinkEndpoint: ep, name: name, fd: fd}, nil
}
func (t *TUN) Name() string { return t.name }
func (t *TUN) Type() string { return "tun" }
func detachQueue(fd int, name string) {
	if ifr, err := unix.NewIfreq(name); err == nil {
		ifr.SetUint16(unix.IFF_DETACH_QUEUE)
		_ = unix.IoctlIfreq(fd, unix.TUNSETQUEUE, ifr)
	}
}
func (t *TUN) Close() {
	t.once.Do(func() {
		// Detach our queue while its fd still identifies the TUN we own.
		// Closing the fd alone can leave the interface registered briefly.
		detachQueue(t.fd, t.name)
		unix.Close(t.fd)
		t.LinkEndpoint.Close()
	})
}
