package vless

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"bimeron/internal/accesskey"
	"golang.getoutline.org/sdk/transport"
)

// Client owns all connections opened for one upstream generation.
type Client struct {
	endpoint           accesskey.Endpoint
	settings           accesskey.VLESS
	id                 [16]byte
	publicKey, shortID []byte
	dialer             net.Dialer
	mu                 sync.Mutex
	closed             bool
	connections        map[*streamConn]struct{}
	packets            map[*packetConn]struct{}
}

var _ transport.StreamDialer = (*Client)(nil)
var _ transport.PacketListener = (*Client)(nil)

func New(profile accesskey.Profile, dialer net.Dialer) (*Client, error) {
	if profile.Type != "vless" {
		return nil, fmt.Errorf("expected VLESS profile")
	}
	v := profile.VLESS
	if err := v.Validate(profile.TCP.Host, profile.TCP.Port); err != nil {
		return nil, err
	}
	if _, err := fingerprint(v.Fingerprint); err != nil {
		return nil, err
	}
	id, err := userID(v.ID)
	if err != nil {
		return nil, err
	}
	key, _ := base64.RawURLEncoding.DecodeString(v.PublicKey)
	sid, _ := hex.DecodeString(v.ShortID)
	return &Client{endpoint: profile.TCP, settings: v, id: id, publicKey: key, shortID: sid, dialer: dialer, connections: make(map[*streamConn]struct{}), packets: make(map[*packetConn]struct{})}, nil
}

func (c *Client) open(ctx context.Context, command byte, destination string) (*streamConn, error) {
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return nil, net.ErrClosed
	}
	header, err := requestHeader(c.id, command, destination, "xtls-rprx-vision")
	if err != nil {
		return nil, err
	}
	setup, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	raw, err := c.dialer.DialContext(setup, "tcp", net.JoinHostPort(c.endpoint.Host, strconv.Itoa(c.endpoint.Port)))
	if err != nil {
		if setup.Err() != nil {
			return nil, setup.Err()
		}
		return nil, fmt.Errorf("VLESS server unavailable")
	}
	ok := false
	defer func() {
		if !ok {
			_ = raw.Close()
		}
	}()
	stop := context.AfterFunc(setup, func() { _ = raw.Close() })
	defer stop()
	_ = raw.SetDeadline(time.Now().Add(15 * time.Second))
	secure, err := realityHandshake(setup, raw, c.settings, c.publicKey, c.shortID)
	if err != nil {
		if setup.Err() != nil {
			return nil, setup.Err()
		}
		return nil, err
	}
	v, err := newVisionConn(secure, raw, c.id)
	if err != nil {
		return nil, err
	}
	if err := v.start(header); err != nil {
		return nil, fmt.Errorf("VLESS request failed")
	}
	_ = raw.SetDeadline(time.Time{})
	conn := &streamConn{visionConn: v, owner: c}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, net.ErrClosed
	}
	c.connections[conn] = struct{}{}
	c.mu.Unlock()
	ok = true
	return conn, nil
}

func (c *Client) DialStream(ctx context.Context, address string) (transport.StreamConn, error) {
	return c.open(ctx, 1, address)
}

func (c *Client) Close() error {
	c.mu.Lock()
	c.closed = true
	connections := make([]*streamConn, 0, len(c.connections))
	for conn := range c.connections {
		connections = append(connections, conn)
	}
	packets := make([]*packetConn, 0, len(c.packets))
	for packet := range c.packets {
		packets = append(packets, packet)
	}
	c.mu.Unlock()
	for _, packet := range packets {
		_ = packet.Close()
	}
	for _, conn := range connections {
		_ = conn.Close()
	}
	return nil
}

type streamConn struct {
	*visionConn
	owner *Client
	once  sync.Once
}

func (s *streamConn) Close() error {
	var err error
	s.once.Do(func() {
		err = s.visionConn.Close()
		s.owner.mu.Lock()
		delete(s.owner.connections, s)
		s.owner.mu.Unlock()
	})
	return err
}
