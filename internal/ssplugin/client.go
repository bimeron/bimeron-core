// Package ssplugin composes Shadowsocks encryption with the embedded
// v2ray-plugin and simple-obfs transports. It never executes profile-supplied code.
package ssplugin

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"bimeron/internal/accesskey"
	"bimeron/internal/proxy"
	"bimeron/internal/simpleobfs"
	"bimeron/internal/streamtransport"
	"bimeron/internal/v2raymux"
	"golang.getoutline.org/sdk/transport"
)

type Client struct {
	endpoint    accesskey.Endpoint
	settings    accesskey.SSPlugin
	dialer      net.Dialer
	rootCAs     *x509.CertPool
	stream      transport.StreamDialer
	pool        *v2raymux.Pool
	mu          sync.Mutex
	closed      bool
	connections map[*wsStream]struct{}
	ctx         context.Context
	cancel      context.CancelFunc
}

func New(p accesskey.Profile, dialer net.Dialer) (*Client, error) {
	if err := p.ValidateShadowTLS(); err != nil {
		return nil, err
	}
	if p.Type != "" && p.Type != "ss" && p.Type != "shadowsocks" {
		return nil, fmt.Errorf("expected Shadowsocks profile")
	}
	if p.SSPlugin == nil {
		return nil, fmt.Errorf("missing Shadowsocks plugin settings")
	}
	if err := p.TCP.Validate(); err != nil {
		return nil, err
	}
	if err := p.SSPlugin.Validate(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	c := &Client{endpoint: p.TCP, settings: *p.SSPlugin, dialer: dialer, connections: make(map[*wsStream]struct{}), ctx: ctx, cancel: cancel}
	var endpoint transport.StreamEndpoint = transport.FuncStreamEndpoint(c.connect)
	if c.settings.Mux > 0 {
		var err error
		// The server plugin replaces this placeholder with its local Shadowsocks
		// address. User destinations remain inside Shadowsocks encryption.
		c.pool, err = v2raymux.New(endpoint, c.settings.Mux, "127.0.0.1:1")
		if err != nil {
			cancel()
			return nil, err
		}
		endpoint = c.pool
	}
	var err error
	c.stream, err = proxy.OutlineStream(p.TCP, endpoint)
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	return c, nil
}

// SetRootCAs configures v2ray-plugin trust before the first connection, for hosts
// with a private trust store. Certificate and hostname verification stay enabled.
func (c *Client) SetRootCAs(roots *x509.CertPool) { c.mu.Lock(); c.rootCAs = roots; c.mu.Unlock() }

func (c *Client) DialStream(ctx context.Context, target string) (transport.StreamConn, error) {
	if c.settings.Name == "obfs-local" {
		return c.dialObfs(ctx, target)
	}
	return c.stream.DialStream(ctx, target)
}

func (c *Client) dialObfs(ctx context.Context, target string) (transport.StreamConn, error) {
	setup, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	stopLifetime := context.AfterFunc(c.ctx, cancel)
	defer stopLifetime()
	var owned *wsStream
	var stop func() bool
	endpoint := transport.FuncStreamEndpoint(func(ctx context.Context) (transport.StreamConn, error) {
		c.mu.Lock()
		closed := c.closed
		c.mu.Unlock()
		if closed {
			return nil, net.ErrClosed
		}
		raw, err := c.dialer.DialContext(ctx, "tcp", net.JoinHostPort(c.endpoint.Host, strconv.Itoa(c.endpoint.Port)))
		if err != nil {
			return nil, err
		}
		stop = context.AfterFunc(ctx, func() { _ = raw.Close() })
		deadline, _ := ctx.Deadline()
		if err := raw.SetDeadline(deadline); err != nil {
			_ = raw.Close()
			return nil, err
		}
		owned = &wsStream{Conn: raw, raw: raw, owner: c}
		wrapped, err := simpleobfs.New(owned, c.settings, c.endpoint.Port)
		if err != nil {
			_ = raw.Close()
			return nil, err
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.closed {
			_ = raw.Close()
			return nil, net.ErrClosed
		}
		c.connections[owned] = struct{}{}
		return wrapped, nil
	})
	defer func() {
		if stop != nil {
			stop()
		}
	}()
	// A per-dial endpoint keeps cancellation attached through SS2022's eager
	// request write without canceling unrelated established connections.
	stream, err := proxy.OutlineStream(c.endpoint, endpoint)
	if err != nil {
		return nil, err
	}
	conn, err := stream.DialStream(setup, target)
	if err != nil {
		if owned != nil {
			_ = owned.Close()
		}
		return nil, err
	}
	if !stop() || setup.Err() != nil {
		_ = conn.Close()
		if err := setup.Err(); err != nil {
			return nil, err
		}
		return nil, context.Canceled
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func (c *Client) connect(ctx context.Context) (transport.StreamConn, error) {
	setup, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	stopClose := context.AfterFunc(c.ctx, cancel)
	defer stopClose()
	c.mu.Lock()
	closed, roots := c.closed, c.rootCAs
	c.mu.Unlock()
	if closed {
		return nil, net.ErrClosed
	}
	raw, err := c.dialer.DialContext(setup, "tcp", net.JoinHostPort(c.endpoint.Host, strconv.Itoa(c.endpoint.Port)))
	if err != nil {
		return nil, fmt.Errorf("plugin server unavailable")
	}
	ready := false
	defer func() {
		if !ready {
			_ = raw.Close()
		}
	}()
	stop := context.AfterFunc(setup, func() { _ = raw.Close() })
	deadline, _ := setup.Deadline()
	_ = raw.SetDeadline(deadline)
	var conn net.Conn = raw
	scheme := "ws"
	if c.settings.TLS {
		conn, err = streamtransport.TLS(setup, raw, c.settings.Host, []string{"http/1.1"}, "", roots)
		if err != nil {
			stop()
			return nil, fmt.Errorf("plugin TLS verification or handshake failed")
		}
		scheme = "wss"
	}
	host := c.settings.Host
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		host = "[" + host + "]"
	}
	ws, err := streamtransport.WebSocket(conn, scheme, host, c.settings.Path, nil)
	if err != nil {
		stop()
		return nil, err
	}
	if !stop() || setup.Err() != nil {
		return nil, context.Canceled
	}
	_ = raw.SetDeadline(time.Time{})
	s := &wsStream{Conn: ws, raw: raw, owner: c}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, net.ErrClosed
	}
	c.connections[s] = struct{}{}
	c.mu.Unlock()
	ready = true
	return s, nil
}

func (c *Client) Close() error {
	c.cancel()
	c.mu.Lock()
	c.closed = true
	connections := make([]*wsStream, 0, len(c.connections))
	for conn := range c.connections {
		connections = append(connections, conn)
	}
	c.mu.Unlock()
	if c.pool != nil {
		_ = c.pool.Close()
	}
	for _, conn := range connections {
		_ = conn.Close()
	}
	return nil
}

// Close the underlying TCP connection directly: websocket.Close can wait for a
// concurrent writer and must not delay shutdown of a stalled connection.
type wsStream struct {
	net.Conn
	raw   net.Conn
	owner *Client
	once  sync.Once
}

func (s *wsStream) Close() error {
	var err error
	s.once.Do(func() { err = s.raw.Close(); s.owner.mu.Lock(); delete(s.owner.connections, s); s.owner.mu.Unlock() })
	return err
}
func (s *wsStream) CloseRead() error  { return s.Close() }
func (s *wsStream) CloseWrite() error { return s.Close() }
