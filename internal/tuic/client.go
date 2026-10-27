package tuic

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"bimeron/internal/accesskey"
	"github.com/quic-go/quic-go"
	"golang.getoutline.org/sdk/transport"
)

type Client struct {
	profile accesskey.Profile
	dialer  net.Dialer
	rootCAs *x509.CertPool
	mu      sync.Mutex
	conn    *quic.Conn
	socket  net.PacketConn
	closed  bool
	packets map[uint16]*packetConn
	nextID  uint16
}

var _ transport.StreamDialer = (*Client)(nil)
var _ transport.PacketListener = (*Client)(nil)

func New(profile accesskey.Profile, dialer net.Dialer) (*Client, error) {
	if profile.Type != "tuic" {
		return nil, fmt.Errorf("expected TUIC profile")
	}
	if err := profile.TUIC.Validate(profile.TCP.Host, profile.TCP.Port); err != nil {
		return nil, err
	}
	return &Client{profile: profile, dialer: dialer, packets: make(map[uint16]*packetConn)}, nil
}

func (c *Client) connection(ctx context.Context) (*quic.Conn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, net.ErrClosed
	}
	if c.conn != nil && c.conn.Context().Err() == nil {
		return c.conn, nil
	}
	if c.conn != nil {
		for _, p := range c.packets {
			p.cancel()
		}
		clear(c.packets)
		_ = c.socket.Close()
		c.conn, c.socket = nil, nil
	}
	resolver := c.dialer.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	ips, err := resolver.LookupNetIP(ctx, "ip", c.profile.TCP.Host)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("TUIC endpoint resolution failed")
	}
	ip := ips[0]
	for _, candidate := range ips {
		if candidate.Unmap().Is4() {
			ip = candidate
			break
		}
	}
	ip = ip.Unmap()
	network, local := "udp4", "0.0.0.0:0"
	if ip.Is6() {
		network, local = "udp6", "[::]:0"
	}
	socket, err := (&net.ListenConfig{Control: c.dialer.Control}).ListenPacket(ctx, network, local)
	if err != nil {
		return nil, fmt.Errorf("TUIC socket failed: %w", err)
	}
	remote := &net.UDPAddr{IP: net.IP(ip.AsSlice()), Port: c.profile.TCP.Port}
	tlsConfig := &tls.Config{ServerName: c.profile.TUIC.ServerName, NextProtos: []string{c.profile.TUIC.ALPN}, MinVersion: tls.VersionTLS13, RootCAs: c.rootCAs}
	setup, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	conn, err := quic.Dial(setup, socket, remote, tlsConfig, &quic.Config{EnableDatagrams: true, KeepAlivePeriod: 10 * time.Second})
	if err != nil {
		_ = socket.Close()
		return nil, fmt.Errorf("TUIC QUIC connection failed: %w", err)
	}
	auth, err := conn.OpenUniStreamSync(setup)
	if err == nil {
		id := c.profile.TUIC.UUID()
		var token []byte
		state := conn.ConnectionState()
		token, err = state.TLS.ExportKeyingMaterial(string(id[:]), []byte(c.profile.TUIC.Password), 32)
		if err == nil {
			request := append([]byte{version, 0}, id[:]...)
			request = append(request, token...)
			err = writeAll(auth, request)
			if err == nil {
				err = auth.Close()
			}
		}
	}
	if err != nil {
		_ = conn.CloseWithError(0, "authentication failed")
		_ = socket.Close()
		return nil, fmt.Errorf("TUIC authentication failed")
	}
	c.conn, c.socket = conn, socket
	go c.readPackets(conn)
	go c.heartbeat(conn)
	return conn, nil
}

func (c *Client) DialStream(ctx context.Context, target string) (transport.StreamConn, error) {
	address, err := addressBytes(target)
	if err != nil {
		return nil, err
	}
	conn, err := c.connection(ctx)
	if err != nil {
		return nil, err
	}
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	if err := writeAll(stream, append([]byte{version, 1}, address...)); err != nil {
		stream.CancelRead(0)
		stream.CancelWrite(0)
		return nil, err
	}
	return &streamConn{Stream: stream, local: conn.LocalAddr(), remote: conn.RemoteAddr()}, nil
}

func (c *Client) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	conn, err := c.connection(ctx)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.conn != conn {
		return nil, net.ErrClosed
	}
	for range 65536 {
		c.nextID++
		if _, used := c.packets[c.nextID]; !used {
			pctx, cancel := context.WithCancel(ctx)
			p := &packetConn{owner: c, conn: conn, id: c.nextID, ctx: pctx, cancel: cancel, incoming: make(chan packet, 64), changed: make(chan struct{})}
			c.packets[p.id] = p
			return p, nil
		}
	}
	return nil, fmt.Errorf("TUIC UDP sessions exhausted")
}

func (c *Client) readPackets(conn *quic.Conn) {
	for {
		stream, err := conn.AcceptUniStream(conn.Context())
		if err != nil {
			return
		}
		go c.readPacketStream(conn, stream)
	}
}

func (c *Client) readPacketStream(conn *quic.Conn, stream *quic.ReceiveStream) {
	defer stream.CancelRead(0)
	var header [10]byte
	if _, err := io.ReadFull(stream, header[:]); err != nil || header[0] != version || header[1] != 2 {
		return
	}
	id := binary.BigEndian.Uint16(header[2:4])
	packetID := binary.BigEndian.Uint16(header[4:6])
	size := int(binary.BigEndian.Uint16(header[8:10]))
	from, err := readAddress(stream)
	if err != nil {
		return
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(stream, data); err != nil {
		return
	}
	c.mu.Lock()
	p := c.packets[id]
	c.mu.Unlock()
	if p == nil || p.conn != conn {
		return
	}
	p.accept(packetID, header[6], header[7], from, data)
}

func (c *Client) heartbeat(conn *quic.Conn) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-conn.Context().Done():
			return
		case <-ticker.C:
			_ = conn.SendDatagram([]byte{version, 4})
		}
	}
}

func (c *Client) Close() error {
	c.mu.Lock()
	c.closed = true
	conn, socket := c.conn, c.socket
	packets := make([]*packetConn, 0, len(c.packets))
	for _, p := range c.packets {
		packets = append(packets, p)
	}
	c.mu.Unlock()
	for _, p := range packets {
		_ = p.Close()
	}
	if conn != nil {
		_ = conn.CloseWithError(0, "closed")
	}
	if socket != nil {
		return socket.Close()
	}
	return nil
}

type streamConn struct {
	*quic.Stream
	local, remote net.Addr
}

func (s *streamConn) LocalAddr() net.Addr  { return s.local }
func (s *streamConn) RemoteAddr() net.Addr { return s.remote }
func (s *streamConn) Close() error {
	s.CancelRead(0)
	s.CancelWrite(0)
	return nil
}
func (s *streamConn) CloseRead() error  { s.CancelRead(0); return nil }
func (s *streamConn) CloseWrite() error { return s.Stream.Close() }

func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}
