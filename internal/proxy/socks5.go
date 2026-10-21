package proxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"bimeron/internal/accesskey"
	"golang.getoutline.org/sdk/transport"
)

// SOCKS5 is a remote upstream. The existing local SOCKS listener is separate.
type SOCKS5 struct {
	Endpoint accesskey.Endpoint
	Username string
	Dialer   net.Dialer
}

var _ transport.StreamDialer = (*SOCKS5)(nil)
var _ transport.PacketListener = (*SOCKS5)(nil)

func (s *SOCKS5) connect(ctx context.Context, command byte, target string) (*net.TCPConn, string, error) {
	endpoint := net.JoinHostPort(s.Endpoint.Host, strconv.Itoa(s.Endpoint.Port))
	conn, err := s.Dialer.DialContext(ctx, "tcp", endpoint)
	if err != nil {
		return nil, "", err
	}
	c := conn.(*net.TCPConn)
	ok := false
	defer func() {
		if !ok {
			_ = c.Close()
		}
	}()
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	method := byte(0)
	if s.Username != "" {
		method = 2
	}
	if _, err = c.Write([]byte{5, 1, method}); err != nil {
		return nil, "", err
	}
	var reply [4]byte
	if _, err = io.ReadFull(c, reply[:2]); err != nil {
		return nil, "", err
	}
	if reply[0] != 5 || reply[1] != method {
		return nil, "", fmt.Errorf("SOCKS5 authentication method rejected")
	}
	if method == 2 {
		user, password := []byte(s.Username), []byte(s.Endpoint.Secret)
		if len(user) == 0 || len(password) == 0 || len(user) > 255 || len(password) > 255 {
			return nil, "", fmt.Errorf("invalid SOCKS5 credentials")
		}
		packet := append([]byte{1, byte(len(user))}, user...)
		packet = append(packet, byte(len(password)))
		packet = append(packet, password...)
		if _, err = c.Write(packet); err != nil {
			return nil, "", err
		}
		if _, err = io.ReadFull(c, reply[:2]); err != nil {
			return nil, "", err
		}
		if reply[0] != 1 || reply[1] != 0 {
			return nil, "", fmt.Errorf("SOCKS5 authentication failed")
		}
	}
	addr, err := socksAddress(target)
	if err != nil {
		return nil, "", err
	}
	request := append([]byte{5, command, 0}, addr...)
	if _, err = c.Write(request); err != nil {
		return nil, "", err
	}
	if _, err = io.ReadFull(c, reply[:]); err != nil {
		return nil, "", err
	}
	if reply[0] != 5 || reply[2] != 0 {
		return nil, "", fmt.Errorf("invalid SOCKS5 response")
	}
	if reply[1] != 0 {
		return nil, "", fmt.Errorf("SOCKS5 command rejected (code %d)", reply[1])
	}
	bound, err := readSocksAddress(c, reply[3])
	if err != nil {
		return nil, "", err
	}
	_ = c.SetDeadline(time.Time{})
	ok = true
	return c, bound, nil
}

func socksAddress(address string) ([]byte, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid SOCKS5 destination")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 0 || port > 65535 {
		return nil, fmt.Errorf("invalid SOCKS5 destination port")
	}
	var b []byte
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			b = append([]byte{1}, v4...)
		} else {
			b = append([]byte{4}, ip.To16()...)
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			return nil, fmt.Errorf("invalid SOCKS5 destination host")
		}
		b = append([]byte{3, byte(len(host))}, host...)
	}
	return binary.BigEndian.AppendUint16(b, uint16(port)), nil
}

func readSocksAddress(r io.Reader, atyp byte) (string, error) {
	var size int
	switch atyp {
	case 1:
		size = 4
	case 4:
		size = 16
	case 3:
		var n [1]byte
		if _, err := io.ReadFull(r, n[:]); err != nil {
			return "", err
		}
		size = int(n[0])
	default:
		return "", fmt.Errorf("invalid SOCKS5 address type")
	}
	b := make([]byte, size+2)
	if _, err := io.ReadFull(r, b); err != nil {
		return "", err
	}
	host := string(b[:size])
	if atyp != 3 {
		host = net.IP(b[:size]).String()
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(b[size:])))), nil
}

func (s *SOCKS5) DialStream(ctx context.Context, target string) (transport.StreamConn, error) {
	c, _, err := s.connect(ctx, 1, target)
	return c, err
}

func (s *SOCKS5) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	// Apply the same interface-binding control as the TCP connection.
	lc := net.ListenConfig{Control: s.Dialer.Control}
	packet, err := lc.ListenPacket(ctx, "udp", "0.0.0.0:0")
	if err != nil {
		return nil, err
	}
	// NAT may change the UDP source port; let the server learn it from packets.
	c, relay, err := s.connect(ctx, 3, "0.0.0.0:0")
	if err != nil {
		_ = packet.Close()
		return nil, err
	}
	host, port, err := net.SplitHostPort(relay)
	if err != nil {
		_ = packet.Close()
		_ = c.Close()
		return nil, err
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber == 0 {
		_ = packet.Close()
		_ = c.Close()
		return nil, fmt.Errorf("invalid SOCKS5 UDP relay port")
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
		host, _, _ = net.SplitHostPort(c.RemoteAddr().String())
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() == nil {
		resolver := s.Dialer.Resolver
		if resolver == nil {
			resolver = net.DefaultResolver
		}
		ips, lookupErr := resolver.LookupIPAddr(ctx, host)
		if lookupErr != nil {
			_ = packet.Close()
			_ = c.Close()
			return nil, fmt.Errorf("could not resolve SOCKS5 UDP relay")
		}
		for _, candidate := range ips {
			if candidate.IP.To4() != nil {
				ip = candidate.IP.To4()
				break
			}
		}
	}
	if ip == nil || ip.To4() == nil {
		_ = packet.Close()
		_ = c.Close()
		return nil, fmt.Errorf("invalid SOCKS5 UDP relay")
	}
	relayAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(ip.String(), port))
	if err != nil {
		_ = packet.Close()
		_ = c.Close()
		return nil, fmt.Errorf("invalid SOCKS5 UDP relay")
	}
	u := &socksPacketConn{PacketConn: packet, control: c, relay: relayAddr}
	go func() { _, _ = io.Copy(io.Discard, c); _ = u.Close() }()
	return u, nil
}

type socksPacketConn struct {
	net.PacketConn
	control *net.TCPConn
	relay   *net.UDPAddr
	once    sync.Once
}

func (c *socksPacketConn) Close() error {
	var err error
	c.once.Do(func() { err = c.PacketConn.Close(); _ = c.control.Close() })
	return err
}

func (c *socksPacketConn) WriteTo(b []byte, address net.Addr) (int, error) {
	header, err := socksAddress(address.String())
	if err != nil {
		return 0, err
	}
	frame := make([]byte, 3, 3+len(header)+len(b))
	frame = append(frame, header...)
	frame = append(frame, b...)
	_, err = c.PacketConn.WriteTo(frame, c.relay)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *socksPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	frame := make([]byte, 65535)
	for {
		n, from, err := c.PacketConn.ReadFrom(frame)
		if err != nil {
			return 0, nil, err
		}
		if from.String() != c.relay.String() || n < 4 || frame[0] != 0 || frame[1] != 0 || frame[2] != 0 {
			continue
		}
		atyp := frame[3]
		address, err := readSocksAddress(bytes.NewReader(frame[4:n]), atyp)
		if err != nil {
			continue
		}
		var size int
		switch atyp {
		case 1:
			size = 4
		case 4:
			size = 16
		case 3:
			size = int(frame[4])
		}
		payload := 4 + size + 2
		if atyp == 3 {
			payload++
		}
		if payload > n {
			continue
		}
		host, _, err := net.SplitHostPort(address)
		if err != nil || net.ParseIP(host) == nil {
			continue
		}
		ip, err := net.ResolveUDPAddr("udp", address)
		if err != nil || ip.IP == nil {
			continue
		}
		count := copy(b, frame[payload:n])
		return count, ip, nil
	}
}
