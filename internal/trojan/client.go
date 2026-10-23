package trojan

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
)

type Client struct {
	endpoint    accesskey.Endpoint
	serverName  string
	password    [56]byte
	dialer      net.Dialer
	rootCAs     *x509.CertPool
	mu          sync.Mutex
	closed      bool
	connections map[*conn]struct{}
}

var _ transport.StreamDialer = (*Client)(nil)
var _ transport.PacketListener = (*Client)(nil)

func New(profile accesskey.Profile, dialer net.Dialer) (*Client, error) {
	if profile.Type != "trojan" {
		return nil, fmt.Errorf("expected Trojan profile")
	}
	if err := profile.Trojan.Validate(profile.TCP.Host, profile.TCP.Port); err != nil {
		return nil, err
	}
	c := &Client{endpoint: profile.TCP, serverName: profile.Trojan.ServerName, dialer: dialer, connections: make(map[*conn]struct{})}
	hash := sha256.Sum224([]byte(profile.Trojan.Password))
	hex.Encode(c.password[:], hash[:])
	return c, nil
}

func (c *Client) open(ctx context.Context, command byte, target string) (*conn, error) {
	address, err := addressBytes(target)
	if err != nil {
		return nil, err
	}
	setup, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	endpoint := net.JoinHostPort(c.endpoint.Host, strconv.Itoa(c.endpoint.Port))
	tlsDialer := tls.Dialer{NetDialer: &c.dialer, Config: &tls.Config{ServerName: c.serverName, MinVersion: tls.VersionTLS12, RootCAs: c.rootCAs}}
	raw, err := tlsDialer.DialContext(setup, "tcp", endpoint)
	if err != nil {
		return nil, fmt.Errorf("Trojan TLS connection failed: %w", err)
	}
	request := make([]byte, 0, 61+len(address))
	request = append(request, c.password[:]...)
	request = append(request, '\r', '\n', command)
	request = append(request, address...)
	request = append(request, '\r', '\n')
	_ = raw.SetWriteDeadline(time.Now().Add(15 * time.Second))
	err = writeAll(raw, request)
	_ = raw.SetWriteDeadline(time.Time{})
	if err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("Trojan request failed")
	}
	owned := &conn{Conn: raw, owner: c}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		_ = raw.Close()
		return nil, net.ErrClosed
	}
	c.connections[owned] = struct{}{}
	c.mu.Unlock()
	return owned, nil
}

func (c *Client) DialStream(ctx context.Context, target string) (transport.StreamConn, error) {
	return c.open(ctx, 1, target)
}

func (c *Client) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	connection, err := c.open(ctx, 3, "0.0.0.0:0")
	if err != nil {
		return nil, err
	}
	p := &packetConn{conn: connection}
	stop := context.AfterFunc(ctx, func() { _ = p.Close() })
	p.stopMu.Lock()
	p.stop = stop
	p.stopMu.Unlock()
	return p, nil
}

func (c *Client) Close() error {
	c.mu.Lock()
	c.closed = true
	connections := make([]*conn, 0, len(c.connections))
	for connection := range c.connections {
		connections = append(connections, connection)
	}
	c.mu.Unlock()
	for _, connection := range connections {
		_ = connection.Close()
	}
	return nil
}

type conn struct {
	net.Conn
	owner *Client
	once  sync.Once
}

func (c *conn) Close() error {
	var err error
	c.once.Do(func() {
		err = c.Conn.Close()
		c.owner.mu.Lock()
		delete(c.owner.connections, c)
		c.owner.mu.Unlock()
	})
	return err
}

func (c *conn) CloseRead() error { return c.Close() }
func (c *conn) CloseWrite() error {
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return c.Close()
}

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
