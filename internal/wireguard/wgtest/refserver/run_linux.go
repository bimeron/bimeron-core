//go:build linux

package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const iface = "wg0"

var tunnelAddresses = []netip.Prefix{
	netip.MustParsePrefix("10.77.0.1/24"),
	netip.MustParsePrefix("fd77::1/64"),
}

func run(server, socket, config string) error {
	cmd := exec.Command(server, "-f", iface)
	// Foreground mode without the kernel-module banner; errors only.
	cmd.Env = []string{"WG_PROCESS_FOREGROUND=1", "LOG_LEVEL=error"}
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if err := cmd.Start(); err != nil {
		return err
	}
	defer func() { _ = cmd.Process.Kill() }()
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()

	if err := setConfig(socket, config, exited); err != nil {
		return err
	}
	link, err := net.InterfaceByName(iface)
	if err != nil {
		return err
	}
	for _, prefix := range tunnelAddresses {
		if err := addAddress(link.Index, prefix); err != nil {
			return fmt.Errorf("address %s: %w", prefix, err)
		}
	}
	if err := linkUp(link.Index); err != nil {
		return fmt.Errorf("link up: %w", err)
	}
	for _, prefix := range tunnelAddresses {
		if err := serveEcho(netip.AddrPortFrom(prefix.Addr(), 7)); err != nil {
			return err
		}
	}
	fmt.Println("ready")

	term := make(chan os.Signal, 1)
	signal.Notify(term, syscall.SIGTERM, os.Interrupt)
	select {
	case <-term:
		return nil
	case err := <-exited:
		return fmt.Errorf("server exited: %v", err)
	}
}

// setConfig waits for the UAPI socket and applies config with one set
// operation of the cross-platform configuration protocol.
func setConfig(socket, config string, exited <-chan error) error {
	deadline := time.Now().Add(10 * time.Second)
	var conn net.Conn
	for {
		var err error
		if conn, err = net.DialTimeout("unix", socket, time.Second); err == nil {
			break
		}
		select {
		case exit := <-exited:
			return fmt.Errorf("server exited: %v", exit)
		default:
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("UAPI socket: %w", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(conn, "set=1\n"+strings.TrimRight(config, "\n")+"\n\n"); err != nil {
		return fmt.Errorf("UAPI write: %w", err)
	}
	reply := bufio.NewReader(conn)
	for {
		line, err := reply.ReadString('\n')
		if err != nil {
			return fmt.Errorf("UAPI reply: %w", err)
		}
		line = strings.TrimSpace(line)
		if line == "" {
			return errors.New("UAPI reply without errno")
		}
		if code, ok := strings.CutPrefix(line, "errno="); ok {
			if code != "0" {
				return fmt.Errorf("UAPI set failed: errno=%s", code)
			}
			return nil
		}
	}
}

func addAddress(index int, prefix netip.Prefix) error {
	family, flags := byte(unix.AF_INET), byte(0)
	if prefix.Addr().Is6() {
		// Skip duplicate address detection so the echo services can bind
		// at once.
		family, flags = unix.AF_INET6, unix.IFA_F_NODAD
	}
	// struct ifaddrmsg: family, prefix length, flags, scope, index.
	body := []byte{family, byte(prefix.Bits()), flags, unix.RT_SCOPE_UNIVERSE, 0, 0, 0, 0}
	binary.NativeEndian.PutUint32(body[4:], uint32(index))
	ip := prefix.Addr().AsSlice()
	for _, kind := range []uint16{unix.IFA_LOCAL, unix.IFA_ADDRESS} {
		attr := make([]byte, 4, 4+len(ip))
		binary.NativeEndian.PutUint16(attr[0:], uint16(4+len(ip)))
		binary.NativeEndian.PutUint16(attr[2:], kind)
		body = append(append(body, attr...), ip...)
	}
	return netlink(unix.RTM_NEWADDR, unix.NLM_F_CREATE|unix.NLM_F_EXCL, body)
}

func linkUp(index int) error {
	// struct ifinfomsg: family, pad, type, index, flags, change.
	body := make([]byte, unix.SizeofIfInfomsg)
	binary.NativeEndian.PutUint32(body[4:], uint32(index))
	binary.NativeEndian.PutUint32(body[8:], unix.IFF_UP)
	binary.NativeEndian.PutUint32(body[12:], unix.IFF_UP)
	return netlink(unix.RTM_NEWLINK, 0, body)
}

// netlink sends one rtnetlink request and waits for its acknowledgement.
func netlink(kind, flags uint16, body []byte) error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	tv := unix.Timeval{Sec: 5}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return err
	}
	msg := make([]byte, unix.NLMSG_HDRLEN, unix.NLMSG_HDRLEN+len(body))
	binary.NativeEndian.PutUint32(msg[0:], uint32(unix.NLMSG_HDRLEN+len(body)))
	binary.NativeEndian.PutUint16(msg[4:], kind)
	binary.NativeEndian.PutUint16(msg[6:], flags|unix.NLM_F_REQUEST|unix.NLM_F_ACK)
	binary.NativeEndian.PutUint32(msg[8:], 1)
	msg = append(msg, body...)
	if err := unix.Sendto(fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	buf := make([]byte, 8192)
	n, _, err := unix.Recvfrom(fd, buf, 0)
	if err != nil {
		return err
	}
	replies, err := syscall.ParseNetlinkMessage(buf[:n])
	if err != nil {
		return err
	}
	for _, reply := range replies {
		if reply.Header.Type == unix.NLMSG_ERROR && len(reply.Data) >= 4 {
			if code := int32(binary.NativeEndian.Uint32(reply.Data)); code != 0 {
				return syscall.Errno(-code)
			}
			return nil
		}
	}
	return errors.New("netlink: no acknowledgement")
}

// serveEcho runs TCP and UDP echo services on at.
func serveEcho(at netip.AddrPort) error {
	l, err := net.Listen("tcp", at.String())
	if err != nil {
		return err
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(time.Minute))
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	pc, err := net.ListenPacket("udp", at.String())
	if err != nil {
		return err
	}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], from)
		}
	}()
	return nil
}
