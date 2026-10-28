package trojan

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"bimeron/internal/accesskey"
	"bimeron/internal/streamtransport"
	"golang.getoutline.org/sdk/transport"
	"golang.org/x/net/websocket"
)

type Client struct {
	grpcTransport *streamtransport.GRPC
	endpoint      accesskey.Endpoint
	settings      accesskey.Trojan
	serverName    string
	password      [56]byte
	dialer        net.Dialer
	rootCAs       *x509.CertPool
	mu            sync.Mutex
	closed        bool
	connections   map[*conn]struct{}
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
	c := &Client{endpoint: profile.TCP, settings: profile.Trojan, serverName: profile.Trojan.ServerName, dialer: dialer, connections: make(map[*conn]struct{})}
	if profile.Trojan.Network == "grpc" {
		t := profile.Trojan
		authority := t.GRPCAuthority
		if authority == "" {
			authority = t.ServerName
		}
		c.grpcTransport = streamtransport.NewGRPC(streamtransport.GRPCConfig{
			Address: net.JoinHostPort(c.endpoint.Host, strconv.Itoa(c.endpoint.Port)), Authority: authority,
			ServiceName: t.GRPCServiceName, MultiMode: t.GRPCMultiMode,
			DialContext: func(ctx context.Context, _ string) (net.Conn, error) { return c.directTransport(ctx) },
		})
	}
	hash := sha256.Sum224([]byte(profile.Trojan.Password))
	hex.Encode(c.password[:], hash[:])
	return c, nil
}

func (c *Client) open(ctx context.Context, command byte, target string) (*conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	address, err := addressBytes(target)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return nil, net.ErrClosed
	}
	raw, err := c.dialTransport(ctx)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer stop()
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
	if c.grpcTransport != nil {
		_ = c.grpcTransport.Close()
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

func (c *Client) dialTransport(ctx context.Context) (net.Conn, error) {
	if c.grpcTransport != nil {
		return c.grpcTransport.DialStream(ctx)
	}
	return c.directTransport(ctx)
}

func (c *Client) directTransport(ctx context.Context) (net.Conn, error) {
	setup, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	endpoint := net.JoinHostPort(c.endpoint.Host, strconv.Itoa(c.endpoint.Port))
	raw, err := c.dialer.DialContext(setup, "tcp", endpoint)
	if err != nil {
		return nil, fmt.Errorf("Trojan server unavailable")
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
	var protocols []string
	if c.settings.ALPN != "" {
		protocols = strings.Split(c.settings.ALPN, ",")
	} else if c.settings.Network == "ws" {
		protocols = []string{"http/1.1"}
	} else if c.settings.Network == "grpc" {
		protocols = []string{"h2"}
	}
	conn, err := streamtransport.TLS(setup, raw, c.serverName, protocols, "", c.rootCAs)
	if err != nil {
		return nil, fmt.Errorf("Trojan TLS connection failed: %w", err)
	}
	if c.settings.Network == "ws" {
		host, path := c.settings.WSHost, c.settings.WSPath
		if host == "" {
			host = c.serverName
		}
		if path == "" {
			path = "/"
		}
		config, err := websocket.NewConfig("wss://"+host+path, "https://"+host)
		if err != nil {
			return nil, fmt.Errorf("invalid Trojan WebSocket settings")
		}
		ws, err := websocket.NewClient(config, conn)
		if err != nil {
			return nil, fmt.Errorf("Trojan WebSocket handshake failed")
		}
		ws.PayloadType = websocket.BinaryFrame
		conn = ws
	}
	_ = raw.SetDeadline(time.Time{})
	ready = true
	return conn, nil
}
