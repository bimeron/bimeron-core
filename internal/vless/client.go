package vless

import (
	"context"
	"crypto/x509"
	"encoding/base64"
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
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	utls "github.com/refraction-networking/utls"
	"golang.getoutline.org/sdk/transport"
	"golang.org/x/net/http2"
	"golang.org/x/net/websocket"
	"google.golang.org/grpc"
)

// Client owns all connections opened for one upstream generation.
type Client struct {
	endpoint           accesskey.Endpoint
	settings           accesskey.VLESS
	id                 [16]byte
	publicKey, shortID []byte
	dialer             net.Dialer
	rootCAs            *x509.CertPool
	shadowTLS          *accesskey.ShadowTLS
	mu                 sync.Mutex
	closed             bool
	connections        map[*streamConn]struct{}
	packets            map[*packetConn]struct{}
	grpcConn           *grpc.ClientConn
	xhttpTransport     *http2.Transport
	xhttpPool          *xhttpMuxPool
	xhttpH3Transport   *http3.Transport
	xhttpQUIC          *quic.Transport
	xhttpPacket        net.PacketConn
	xhttpDownload      *Client
}

var _ transport.StreamDialer = (*Client)(nil)
var _ transport.PacketListener = (*Client)(nil)

func New(profile accesskey.Profile, dialer net.Dialer) (*Client, error) {
	if err := profile.ValidateShadowTLS(); err != nil {
		return nil, err
	}
	if profile.Type != "vless" {
		return nil, fmt.Errorf("expected VLESS profile")
	}
	v := profile.VLESS
	if err := v.Validate(profile.TCP.Host, profile.TCP.Port); err != nil {
		return nil, err
	}
	if v.Fingerprint != "" {
		if _, err := fingerprint(v.Fingerprint); err != nil {
			return nil, err
		}
	}
	id, err := userID(v.ID)
	if err != nil {
		return nil, err
	}
	key, _ := base64.RawURLEncoding.DecodeString(v.PublicKey)
	sid, _ := hex.DecodeString(v.ShortID)
	return &Client{endpoint: profile.TCP, settings: v, id: id, publicKey: key, shortID: sid, dialer: dialer, shadowTLS: profile.ShadowTLS, connections: make(map[*streamConn]struct{}), packets: make(map[*packetConn]struct{})}, nil
}

func (c *Client) open(ctx context.Context, command byte, destination string) (*streamConn, error) {
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return nil, net.ErrClosed
	}
	header, err := requestHeader(c.id, command, destination, c.settings.Flow)
	if err != nil {
		return nil, err
	}
	if c.settings.Network == "grpc" || c.settings.Network == "xhttp" {
		var conn net.Conn
		if c.settings.Network == "grpc" {
			conn, err = c.grpcStream(ctx)
		} else {
			conn, err = c.xhttpStream(ctx)
		}
		if err != nil {
			return nil, err
		}
		_ = conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
		if n, writeErr := conn.Write(header); writeErr != nil || n != len(header) {
			_ = conn.Close()
			return nil, fmt.Errorf("VLESS request failed")
		}
		_ = conn.SetWriteDeadline(time.Time{})
		owned := &streamConn{StreamConn: &plainConn{Conn: conn}, owner: c}
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			_ = owned.Close()
			return nil, net.ErrClosed
		}
		c.connections[owned] = struct{}{}
		c.mu.Unlock()
		return owned, nil
	}
	setup, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	raw, err := streamtransport.Dial(setup, c.dialer, net.JoinHostPort(c.endpoint.Host, strconv.Itoa(c.endpoint.Port)), c.shadowTLS, c.rootCAs)
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
	var conn net.Conn
	if c.settings.Security == "reality" {
		conn, err = realityHandshake(setup, raw, c.settings, c.publicKey, c.shortID)
	} else {
		conn, err = c.tlsHandshake(setup, raw)
	}
	if err != nil {
		if setup.Err() != nil {
			return nil, setup.Err()
		}
		return nil, err
	}
	if c.settings.Network == "ws" {
		early := []byte(nil)
		if c.settings.WSEarlyData > 0 && len(header) <= c.settings.WSEarlyData {
			early = header
		}
		conn, err = c.webSocket(conn, early)
		if err != nil {
			return nil, err
		}
		if early != nil {
			header = nil
		}
	}
	var stream transport.StreamConn
	if c.settings.Flow != "" {
		v, visionErr := newVisionConn(conn.(*utls.UConn), raw, c.id)
		if visionErr != nil {
			return nil, visionErr
		}
		if err = v.start(header); err == nil {
			stream = v
		}
	} else {
		var written int
		written, err = conn.Write(header)
		if err == nil && written != len(header) {
			err = io.ErrShortWrite
		}
		if err == nil {
			stream = &plainConn{Conn: conn}
		}
	}
	if err != nil {
		return nil, fmt.Errorf("VLESS request failed")
	}
	_ = raw.SetDeadline(time.Time{})
	owned := &streamConn{StreamConn: stream, owner: c}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, net.ErrClosed
	}
	c.connections[owned] = struct{}{}
	c.mu.Unlock()
	ok = true
	return owned, nil
}

func (c *Client) tlsHandshake(ctx context.Context, raw net.Conn) (net.Conn, error) {
	name := c.settings.ServerName
	if name == "" {
		name = c.endpoint.Host
	}
	protocols := []string(nil)
	if c.settings.ALPN != "" {
		protocols = strings.Split(c.settings.ALPN, ",")
	} else if c.settings.Network == "ws" {
		protocols = []string{"http/1.1"}
	} else if c.settings.Network == "grpc" || c.settings.Network == "xhttp" {
		protocols = []string{"h2"}
	}
	conn, err := streamtransport.TLS(ctx, raw, name, protocols, c.settings.Fingerprint, c.rootCAs)
	if err != nil {
		return nil, fmt.Errorf("VLESS TLS handshake failed: %w", err)
	}
	return conn, nil
}

// SetRootCAs supplies a trust store before opening transport streams.
func (c *Client) SetRootCAs(roots *x509.CertPool) { c.rootCAs = roots }

func (c *Client) webSocket(conn net.Conn, early []byte) (net.Conn, error) {
	host := c.settings.WSHost
	if host == "" {
		host = c.settings.ServerName
	}
	if host == "" {
		host = c.endpoint.Host
	}
	path := c.settings.WSPath
	if path == "" {
		path = "/"
	}
	config, err := websocket.NewConfig("wss://"+host+path, "https://"+host)
	if err != nil {
		return nil, fmt.Errorf("invalid VLESS WebSocket settings")
	}
	if early != nil {
		config.Protocol = []string{base64.RawURLEncoding.EncodeToString(early)}
	}
	ws, err := websocket.NewClient(config, conn)
	if err != nil {
		return nil, fmt.Errorf("VLESS WebSocket handshake failed")
	}
	ws.PayloadType = websocket.BinaryFrame
	return ws, nil
}

func (c *Client) DialStream(ctx context.Context, address string) (transport.StreamConn, error) {
	return c.open(ctx, 1, address)
}

// DialTransport opens a protocol-neutral gRPC or XHTTP byte stream. The caller
// owns the returned stream and writes its own protocol request framing.
func (c *Client) DialTransport(ctx context.Context) (net.Conn, error) {
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return nil, net.ErrClosed
	}
	switch c.settings.Network {
	case "grpc":
		return c.grpcStream(ctx)
	case "xhttp":
		return c.xhttpStream(ctx)
	case "tcp":
		if c.settings.Security != "reality" {
			return nil, fmt.Errorf("unsupported raw transport")
		}
		setup, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		raw, err := streamtransport.Dial(setup, c.dialer, net.JoinHostPort(c.endpoint.Host, strconv.Itoa(c.endpoint.Port)), c.shadowTLS, c.rootCAs)
		if err != nil {
			return nil, err
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
		conn, err := realityHandshake(setup, raw, c.settings, c.publicKey, c.shortID)
		if err != nil {
			return nil, err
		}
		_ = raw.SetDeadline(time.Time{})
		ready = true
		return conn, nil
	default:
		return nil, fmt.Errorf("unsupported raw transport")
	}
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
	grpcConn := c.grpcConn
	c.grpcConn = nil
	xhttpTransport := c.xhttpTransport
	c.xhttpTransport = nil
	xhttpPool := c.xhttpPool
	c.xhttpPool = nil
	xhttpH3Transport := c.xhttpH3Transport
	c.xhttpH3Transport = nil
	xhttpQUIC := c.xhttpQUIC
	c.xhttpQUIC = nil
	xhttpPacket := c.xhttpPacket
	c.xhttpPacket = nil
	xhttpDownload := c.xhttpDownload
	c.xhttpDownload = nil
	c.mu.Unlock()
	for _, packet := range packets {
		_ = packet.Close()
	}
	for _, conn := range connections {
		_ = conn.Close()
	}
	if grpcConn != nil {
		_ = grpcConn.Close()
	}
	if xhttpTransport != nil {
		xhttpTransport.CloseIdleConnections()
	}
	if xhttpPool != nil {
		xhttpPool.Close()
	}
	if xhttpH3Transport != nil {
		_ = xhttpH3Transport.Close()
	}
	if xhttpQUIC != nil {
		_ = xhttpQUIC.Close()
	}
	if xhttpPacket != nil {
		_ = xhttpPacket.Close()
	}
	if xhttpDownload != nil {
		_ = xhttpDownload.Close()
	}
	return nil
}

type streamConn struct {
	transport.StreamConn
	owner *Client
	once  sync.Once
}

func (s *streamConn) Close() error {
	var err error
	s.once.Do(func() {
		err = s.StreamConn.Close()
		s.owner.mu.Lock()
		delete(s.owner.connections, s)
		s.owner.mu.Unlock()
	})
	return err
}
