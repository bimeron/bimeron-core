package trojan

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

func addressBytes(target string) ([]byte, error) {
	host, portText, err := net.SplitHostPort(target)
	if err != nil || host == "" {
		return nil, fmt.Errorf("invalid Trojan destination")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 0 || port > 65535 {
		return nil, fmt.Errorf("invalid Trojan destination")
	}
	var b []byte
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Is4() || ip.Is4In6() {
			v4 := ip.Unmap().As4()
			b = append([]byte{1}, v4[:]...)
		} else {
			v6 := ip.As16()
			b = append([]byte{4}, v6[:]...)
		}
	} else {
		if len(host) > 255 || strings.ContainsAny(host, " /\t\r\n") {
			return nil, fmt.Errorf("invalid Trojan destination")
		}
		b = append([]byte{3, byte(len(host))}, host...)
	}
	return binary.BigEndian.AppendUint16(b, uint16(port)), nil
}

func readAddress(r io.Reader) (net.Addr, error) {
	var kind [1]byte
	if _, err := io.ReadFull(r, kind[:]); err != nil {
		return nil, err
	}
	var host string
	switch kind[0] {
	case 1:
		var b [4]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return nil, err
		}
		host = net.IP(b[:]).String()
	case 4:
		var b [16]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return nil, err
		}
		host = net.IP(b[:]).String()
	case 3:
		var n [1]byte
		if _, err := io.ReadFull(r, n[:]); err != nil {
			return nil, err
		}
		if n[0] == 0 {
			return nil, fmt.Errorf("invalid Trojan response address")
		}
		b := make([]byte, int(n[0]))
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, err
		}
		host = string(b)
	default:
		return nil, fmt.Errorf("invalid Trojan response address")
	}
	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return nil, err
	}
	return trojanAddr(net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port[:]))))), nil
}

type trojanAddr string

func (a trojanAddr) Network() string { return "udp" }
func (a trojanAddr) String() string  { return string(a) }

type packetConn struct {
	conn      *conn
	writeMu   sync.Mutex
	stopMu    sync.Mutex
	stop      func() bool
	closeOnce sync.Once
}

func (p *packetConn) WriteTo(b []byte, address net.Addr) (int, error) {
	if address == nil || len(b) > 65535 {
		return 0, fmt.Errorf("invalid Trojan datagram")
	}
	encoded, err := addressBytes(address.String())
	if err != nil {
		return 0, err
	}
	frame := binary.BigEndian.AppendUint16(encoded, uint16(len(b)))
	frame = append(frame, '\r', '\n')
	frame = append(frame, b...)
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	if err := writeAll(p.conn, frame); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (p *packetConn) ReadFrom(b []byte) (int, net.Addr, error) {
	address, err := readAddress(p.conn)
	if err != nil {
		return 0, nil, err
	}
	var tail [4]byte
	if _, err := io.ReadFull(p.conn, tail[:]); err != nil {
		return 0, nil, err
	}
	if tail[2] != '\r' || tail[3] != '\n' {
		return 0, nil, fmt.Errorf("invalid Trojan datagram")
	}
	n := int(binary.BigEndian.Uint16(tail[:2]))
	if n > len(b) {
		_, err := io.CopyN(io.Discard, p.conn, int64(n))
		if err != nil {
			return 0, nil, err
		}
		return 0, nil, fmt.Errorf("Trojan datagram exceeds buffer")
	}
	_, err = io.ReadFull(p.conn, b[:n])
	return n, address, err
}

func (p *packetConn) Close() error {
	var err error
	p.closeOnce.Do(func() {
		p.stopMu.Lock()
		stop := p.stop
		p.stopMu.Unlock()
		if stop != nil {
			stop()
		}
		err = p.conn.Close()
	})
	return err
}
func (p *packetConn) LocalAddr() net.Addr                { return trojanAddr("0.0.0.0:0") }
func (p *packetConn) SetDeadline(t time.Time) error      { return p.conn.SetDeadline(t) }
func (p *packetConn) SetReadDeadline(t time.Time) error  { return p.conn.SetReadDeadline(t) }
func (p *packetConn) SetWriteDeadline(t time.Time) error { return p.conn.SetWriteDeadline(t) }
