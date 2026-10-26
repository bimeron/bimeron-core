package hysteria2

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"bimeron/internal/accesskey"
	hy "github.com/apernet/hysteria/core/v2/client"
	"github.com/apernet/quic-go"
	"golang.getoutline.org/sdk/transport"
)

type Client struct{ upstream hy.Client }

var _ transport.StreamDialer = (*Client)(nil)
var _ transport.PacketListener = (*Client)(nil)

type connFactory struct {
	ctx     context.Context
	control net.Dialer
	stop    func() bool
}

func (f *connFactory) New(addr net.Addr) (net.PacketConn, error) {
	network := "udp4"
	if a, ok := addr.(*net.UDPAddr); ok && a.IP.To4() == nil {
		network = "udp6"
	}
	p, err := (&net.ListenConfig{Control: f.control.Control}).ListenPacket(f.ctx, network, ":0")
	if err != nil {
		return nil, err
	}
	f.stop = context.AfterFunc(f.ctx, func() { _ = p.Close() })
	return p, nil
}

func New(ctx context.Context, profile accesskey.Profile, dialer net.Dialer) (*Client, error) {
	return newClient(ctx, profile, dialer, nil)
}

func newClient(ctx context.Context, profile accesskey.Profile, dialer net.Dialer, roots *x509.CertPool) (*Client, error) {
	if profile.Type != "hysteria2" {
		return nil, fmt.Errorf("expected Hysteria2 profile")
	}
	if err := profile.Hysteria2.Validate(profile.TCP.Host, profile.TCP.Port); err != nil {
		return nil, err
	}
	address := net.JoinHostPort(profile.TCP.Host, strconv.Itoa(profile.TCP.Port))
	endpoint, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, fmt.Errorf("invalid Hysteria2 server endpoint")
	}
	factory := &connFactory{ctx: ctx, control: dialer}
	fingerprint := quic.QUICFingerprint(profile.Hysteria2.Fingerprint)
	if fingerprint == "firefox" {
		fingerprint = quic.QUICFirefox116
	}
	upstream, info, err := hy.NewClient(&hy.Config{ConnFactory: factory, ServerAddr: endpoint, Auth: profile.Hysteria2.Password, QUICConfig: hy.QUICConfig{Fingerprint: fingerprint}, TLSConfig: hy.TLSConfig{ServerName: profile.Hysteria2.ServerName, RootCAs: roots}})
	if factory.stop != nil {
		factory.stop()
	}
	if err != nil {
		return nil, fmt.Errorf("Hysteria2 connection failed")
	}
	if err := ctx.Err(); err != nil {
		_ = upstream.Close()
		return nil, err
	}
	if !info.UDPEnabled {
		_ = upstream.Close()
		return nil, fmt.Errorf("Hysteria2 server disabled UDP")
	}
	return &Client{upstream: upstream}, nil
}

func (c *Client) DialStream(ctx context.Context, address string) (transport.StreamConn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	conn, err := c.upstream.TCP(address)
	if err != nil {
		return nil, err
	}
	return streamConn{Conn: conn}, nil
}

type streamConn struct{ net.Conn }

// The upstream client exposes net.Conn but not its QUIC stream's half-close.
// Keep the other direction alive until the owning connection is closed.
func (c streamConn) CloseRead() error {
	if v, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return v.CloseRead()
	}
	return nil
}
func (c streamConn) CloseWrite() error {
	if v, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return v.CloseWrite()
	}
	return nil
}

func (c *Client) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	u, err := c.upstream.UDP()
	if err != nil {
		return nil, err
	}
	p := &packetConn{upstream: u, changed: make(chan struct{}), done: make(chan struct{}), incoming: make(chan packet, 1)}
	stop := context.AfterFunc(ctx, func() { _ = p.Close() })
	p.mu.Lock()
	if p.closed {
		stop()
	} else {
		p.stop = stop
	}
	p.mu.Unlock()
	go p.receive()
	return p, nil
}

func (c *Client) Close() error { return c.upstream.Close() }

type packet struct {
	data []byte
	addr string
	err  error
}
type packetConn struct {
	upstream                    hy.HyUDPConn
	mu                          sync.Mutex
	writeMu                     sync.Mutex
	closed                      bool
	readDeadline, writeDeadline time.Time
	changed                     chan struct{}
	done                        chan struct{}
	incoming                    chan packet
	stop                        func() bool
}

func (p *packetConn) receive() {
	for {
		data, addr, err := p.upstream.Receive()
		select {
		case p.incoming <- packet{data, addr, err}:
		case <-p.done:
			return
		}
		if err != nil {
			return
		}
	}
}

func (p *packetConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		p.mu.Lock()
		deadline, changed := p.readDeadline, p.changed
		p.mu.Unlock()
		var timer <-chan time.Time
		if !deadline.IsZero() {
			timer = time.After(time.Until(deadline))
		}
		select {
		case v := <-p.incoming:
			if v.err != nil {
				return 0, nil, v.err
			}
			if _, _, err := net.SplitHostPort(v.addr); err != nil {
				return 0, nil, fmt.Errorf("invalid Hysteria2 UDP source")
			}
			return copy(b, v.data), packetAddr(v.addr), nil
		case <-timer:
			return 0, nil, timeoutError{}
		case <-changed:
		case <-p.done:
			return 0, nil, net.ErrClosed
		}
	}
}

func (p *packetConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if addr == nil {
		return 0, fmt.Errorf("missing Hysteria2 UDP destination")
	}
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	p.mu.Lock()
	deadline, closed := p.writeDeadline, p.closed
	p.mu.Unlock()
	if closed {
		return 0, net.ErrClosed
	}
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return 0, timeoutError{}
	}
	if err := p.upstream.Send(b, addr.String()); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (p *packetConn) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	close(p.done)
	stop := p.stop
	p.mu.Unlock()
	if stop != nil {
		stop()
	}
	return p.upstream.Close()
}

func (p *packetConn) LocalAddr() net.Addr { return &net.UDPAddr{} }
func (p *packetConn) SetDeadline(t time.Time) error {
	_ = p.SetReadDeadline(t)
	return p.SetWriteDeadline(t)
}
func (p *packetConn) SetReadDeadline(t time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return net.ErrClosed
	}
	p.readDeadline = t
	close(p.changed)
	p.changed = make(chan struct{})
	return nil
}
func (p *packetConn) SetWriteDeadline(t time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return net.ErrClosed
	}
	p.writeDeadline = t
	return nil
}

type timeoutError struct{}

type packetAddr string

func (a packetAddr) Network() string { return "udp" }
func (a packetAddr) String() string  { return string(a) }

func (timeoutError) Error() string   { return "Hysteria2 UDP deadline exceeded" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }
