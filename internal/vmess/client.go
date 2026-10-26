package vmess

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"bimeron/internal/accesskey"
	"golang.getoutline.org/sdk/transport"
	"golang.org/x/net/websocket"
)

type Client struct {
	endpoint    accesskey.Endpoint
	settings    accesskey.VMess
	id          [16]byte
	dialer      net.Dialer
	rootCAs     *x509.CertPool
	mu          sync.Mutex
	closed      bool
	connections map[*streamConn]struct{}
	packets     map[*packetConn]struct{}
}

var _ transport.StreamDialer = (*Client)(nil)
var _ transport.PacketListener = (*Client)(nil)

func New(profile accesskey.Profile, dialer net.Dialer) (*Client, error) {
	if profile.Type != "vmess" {
		return nil, fmt.Errorf("expected VMess profile")
	}
	if err := profile.VMess.Validate(profile.TCP.Host, profile.TCP.Port); err != nil {
		return nil, err
	}
	idText := profile.VMess.ID
	idBytes, err := hex.DecodeString(idText[0:8] + idText[9:13] + idText[14:18] + idText[19:23] + idText[24:])
	if err != nil {
		return nil, fmt.Errorf("invalid VMess user ID")
	}
	c := &Client{endpoint: profile.TCP, settings: profile.VMess, dialer: dialer, connections: make(map[*streamConn]struct{}), packets: make(map[*packetConn]struct{})}
	copy(c.id[:], idBytes)
	return c, nil
}

func (c *Client) open(ctx context.Context, command byte, target string) (*streamConn, error) {
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return nil, net.ErrClosed
	}
	security := c.settings.Security
	if security == "auto" {
		security = "aes-128-gcm"
	}
	securityByte := byte(3)
	if security == "chacha20-poly1305" {
		securityByte = 4
	}
	header, iv, key, response, err := requestHeader(c.id, command, target, securityByte)
	if err != nil {
		return nil, err
	}
	setup, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	raw, err := c.dialer.DialContext(setup, "tcp", net.JoinHostPort(c.endpoint.Host, strconv.Itoa(c.endpoint.Port)))
	if err != nil {
		return nil, fmt.Errorf("VMess server unavailable")
	}
	ready := false
	defer func() {
		if !ready {
			_ = raw.Close()
		}
	}()
	stop := context.AfterFunc(setup, func() { _ = raw.Close() })
	defer stop()
	_ = raw.SetDeadline(time.Now().Add(15 * time.Second))
	tlsConn := tls.Client(raw, &tls.Config{ServerName: c.settings.ServerName, MinVersion: tls.VersionTLS12, RootCAs: c.rootCAs, NextProtos: func() []string {
		if c.settings.Network == "ws" {
			return []string{"http/1.1"}
		}
		return nil
	}()})
	if err = tlsConn.HandshakeContext(setup); err != nil {
		return nil, fmt.Errorf("VMess TLS handshake failed: %w", err)
	}
	var conn net.Conn = tlsConn
	if c.settings.Network == "ws" {
		host := c.settings.WSHost
		if host == "" {
			host = c.settings.ServerName
		}
		config, configErr := websocket.NewConfig("wss://"+host+c.settings.WSPath, "https://"+host)
		if configErr != nil {
			return nil, fmt.Errorf("invalid VMess WebSocket settings")
		}
		ws, wsErr := websocket.NewClient(config, conn)
		if wsErr != nil {
			return nil, fmt.Errorf("VMess WebSocket handshake failed")
		}
		ws.PayloadType = websocket.BinaryFrame
		conn = ws
	}
	if err = writeAll(conn, header); err != nil {
		return nil, fmt.Errorf("VMess request failed")
	}
	writer, err := newChunkCodec(conn, key, iv, security)
	if err != nil {
		return nil, err
	}
	responseKey := sha256.Sum256(key[:])
	responseIV := sha256.Sum256(iv[:])
	var rk, ri [16]byte
	copy(rk[:], responseKey[:16])
	copy(ri[:], responseIV[:16])
	reader, err := newChunkCodec(conn, rk, ri, security)
	if err != nil {
		return nil, err
	}
	_ = raw.SetDeadline(time.Time{})
	owned := &streamConn{Conn: conn, owner: c, writer: writer, reader: reader, responseKey: key, responseIV: iv, expected: response}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, net.ErrClosed
	}
	c.connections[owned] = struct{}{}
	c.mu.Unlock()
	ready = true
	return owned, nil
}

func (c *Client) DialStream(ctx context.Context, target string) (transport.StreamConn, error) {
	return c.open(ctx, 1, target)
}

func (c *Client) Close() error {
	c.mu.Lock()
	c.closed = true
	connections := make([]*streamConn, 0, len(c.connections))
	for x := range c.connections {
		connections = append(connections, x)
	}
	packets := make([]*packetConn, 0, len(c.packets))
	for x := range c.packets {
		packets = append(packets, x)
	}
	c.mu.Unlock()
	for _, p := range packets {
		_ = p.Close()
	}
	for _, x := range connections {
		_ = x.Close()
	}
	return nil
}

type streamConn struct {
	net.Conn
	owner                   *Client
	writer, reader          *chunkCodec
	responseKey, responseIV [16]byte
	expected                byte
	readOnce                sync.Once
	readMu                  sync.Mutex
	readErr                 error
	writeMu                 sync.Mutex
	buffer                  []byte
	closeOnce               sync.Once
}

func (s *streamConn) Read(b []byte) (int, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	s.readOnce.Do(func() { s.readErr = readResponseHeader(s.Conn, s.responseKey, s.responseIV, s.expected) })
	if s.readErr != nil {
		return 0, s.readErr
	}
	if len(s.buffer) == 0 {
		frame, err := s.reader.readFrame()
		if err != nil {
			return 0, err
		}
		s.buffer = frame
	}
	n := copy(b, s.buffer)
	s.buffer = s.buffer[n:]
	return n, nil
}

func (s *streamConn) Write(b []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	for offset := 0; offset < len(b); {
		end := offset + 8192 - 82
		if end > len(b) {
			end = len(b)
		}
		if err := s.writer.writeFrame(b[offset:end]); err != nil {
			return offset, err
		}
		offset = end
	}
	return len(b), nil
}

func (s *streamConn) Close() error {
	var err error
	s.closeOnce.Do(func() { err = s.Conn.Close(); s.owner.mu.Lock(); delete(s.owner.connections, s); s.owner.mu.Unlock() })
	return err
}

func (s *streamConn) CloseRead() error { return s.Close() }
func (s *streamConn) CloseWrite() error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := s.writer.writeFrame(nil); err != nil {
		return err
	}
	if half, ok := s.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return nil
}

var _ io.ReadWriteCloser = (*streamConn)(nil)
