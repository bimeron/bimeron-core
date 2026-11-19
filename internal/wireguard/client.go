package wireguard

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"bimeron/internal/wgconf"
	"golang.getoutline.org/sdk/transport"
)

// Modes of [Routing] AllowedIPsMode.
const (
	ModeDirect = "direct"
	ModeBlock  = "block"
	ModeIgnore = "ignore"
	ModeOnly   = "only"
)

// route is where the scope sends one destination.
type route int

const (
	viaTunnel route = iota
	viaDirect
	blocked
)

// Options configures a client generation. Endpoint is the peer endpoint
// already resolved on the outbound path.
type Options struct {
	Config   *wgconf.Config
	Endpoint netip.AddrPort
	// Mode is an AllowedIPsMode value; empty means direct.
	Mode string
	// Outbound opens sockets on the physical path: the WireGuard socket and
	// direct connections for destinations outside AllowedIPs.
	Outbound net.Dialer
	// DNS lists resolver IPs (port 53) for names given to DialStream. The
	// queries follow the same scope as other traffic.
	DNS []string
}

// Client is one WireGuard device generation. It is safe for concurrent use.
type Client struct {
	tunnel   tunnel
	bind     *Bind
	outbound net.Dialer
	allowed  []netip.Prefix
	mode     string
	guardV6  bool
	dns      []netip.AddrPort
	closed   chan struct{}
	once     sync.Once
}

var _ transport.StreamDialer = (*Client)(nil)
var _ transport.PacketListener = (*Client)(nil)

// Errors carry no addresses, keys or engine text.
var (
	ErrClosed    = errors.New("WireGuard client closed")
	ErrBlocked   = errors.New("destination outside WireGuard AllowedIPs is blocked")
	errResolve   = errors.New("WireGuard name resolution failed")
	errHandshake = errors.New("WireGuard handshake did not complete")
	errTunnel    = errors.New("WireGuard tunnel connection failed")
)

// New starts a device. It does not wait for the handshake; use
// WaitHandshake before reporting the session as connected.
func New(o Options) (*Client, error) {
	return newWithEngine(o, startAWG)
}

func newWithEngine(o Options, start engine) (*Client, error) {
	c := o.Config
	if c == nil || !o.Endpoint.IsValid() {
		return nil, errors.New("invalid WireGuard options")
	}
	mode := o.Mode
	if mode == "" {
		mode = ModeDirect
	}
	switch mode {
	case ModeDirect, ModeBlock, ModeIgnore, ModeOnly:
	default:
		return nil, errors.New("invalid WireGuard AllowedIPs mode")
	}
	allowed := c.Peer.AllowedIPs
	peerAllowed := allowed
	if mode == ModeIgnore {
		peerAllowed = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}
	}
	summary := wgconf.Summarize(allowed)
	client := &Client{
		outbound: o.Outbound,
		allowed:  allowed,
		mode:     mode,
		guardV6:  summary.Coverage == wgconf.CoverageIPv4Only,
		closed:   make(chan struct{}),
	}
	for _, s := range o.DNS {
		if a, err := netip.ParseAddr(s); err == nil {
			client.dns = append(client.dns, netip.AddrPortFrom(a.Unmap(), 53))
		}
	}
	lc := net.ListenConfig{Control: o.Outbound.Control}
	client.bind = NewBind(lc.ListenPacket, o.Endpoint)
	t, err := start(tunnelConfig{
		Addresses: c.LocalAddresses(),
		MTU:       c.TunnelMTU(),
		UAPI:      c.UAPI(o.Endpoint, peerAllowed),
		PublicKey: c.Peer.PublicKey,
		Bind:      client.bind,
	})
	if err != nil {
		return nil, errEngine
	}
	client.tunnel = t
	return client, nil
}

// scope decides where traffic that Bimeron's policy sent to the upstream
// goes. Bimeron block and direct rules were already applied by the caller.
func (c *Client) scope(ip netip.Addr) route {
	ip = ip.Unmap()
	if c.mode == ModeIgnore {
		return viaTunnel
	}
	for _, p := range c.allowed {
		if p.Contains(ip) {
			return viaTunnel
		}
	}
	if c.mode == ModeBlock || (ip.Is6() && c.guardV6) {
		return blocked
	}
	return viaDirect
}

// WaitHandshake starts a handshake and waits until it completes or ctx ends.
func (c *Client) WaitHandshake(ctx context.Context) error {
	since := time.Now()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	nudge := time.Now()
	c.tunnel.Initiate()
	for {
		if !c.tunnel.LastHandshake().Before(since) {
			return nil
		}
		select {
		case <-ctx.Done():
			return errHandshake
		case <-c.closed:
			return ErrClosed
		case now := <-ticker.C:
			// The engine retries on its own; a periodic nudge covers a
			// dropped first keepalive before any session exists.
			if now.Sub(nudge) >= 5*time.Second {
				nudge = now
				c.tunnel.Initiate()
			}
		}
	}
}

// LastHandshake reports the most recent completed handshake.
func (c *Client) LastHandshake() time.Time { return c.tunnel.LastHandshake() }

// Probe checks that the peer still answers. A handshake within the session
// lifetime is enough; otherwise it forces one.
func (c *Client) Probe(ctx context.Context) error {
	if time.Since(c.tunnel.LastHandshake()) < 150*time.Second {
		return nil
	}
	return c.WaitHandshake(ctx)
}

// Traffic reports encrypted bytes on the wire.
func (c *Client) Traffic() (sent, received uint64) { return c.bind.Traffic() }

// Close stops the device. Connections opened through it fail afterwards.
func (c *Client) Close() error {
	c.once.Do(func() {
		close(c.closed)
		_ = c.tunnel.Close()
	})
	return nil
}

func (c *Client) isClosed() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}

// DialStream connects to an IP or name. Names are resolved through the
// configured resolvers, routed by scope.
func (c *Client) DialStream(ctx context.Context, address string) (transport.StreamConn, error) {
	if c.isClosed() {
		return nil, ErrClosed
	}
	to, err := c.resolve(ctx, address)
	if err != nil {
		return nil, err
	}
	switch c.scope(to.Addr()) {
	case blocked:
		return nil, ErrBlocked
	case viaDirect:
		conn, err := c.outbound.DialContext(ctx, "tcp", to.String())
		if err != nil {
			return nil, err
		}
		if tcp, ok := conn.(*net.TCPConn); ok {
			return tcp, nil
		}
		_ = conn.Close()
		return nil, errTunnel
	}
	conn, err := c.tunnel.DialTCP(ctx, to)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errTunnel
	}
	stream, ok := conn.(transport.StreamConn)
	if !ok {
		_ = conn.Close()
		return nil, errTunnel
	}
	return stream, nil
}

func (c *Client) resolve(ctx context.Context, address string) (netip.AddrPort, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return netip.AddrPort{}, err
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return netip.AddrPort{}, errors.New("invalid port")
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return netip.AddrPortFrom(ip.Unmap(), uint16(port)), nil
	}
	if len(c.dns) == 0 {
		return netip.AddrPort{}, errResolve
	}
	resolver := &net.Resolver{PreferGo: true, Dial: c.dialDNS}
	ips, err := resolver.LookupNetIP(ctx, "ip", strings.TrimSuffix(host, "."))
	if err != nil || len(ips) == 0 {
		return netip.AddrPort{}, errResolve
	}
	// Prefer an address the scope does not block, IPv4 first.
	best := netip.Addr{}
	for _, ip := range ips {
		ip = ip.Unmap()
		if c.scope(ip) == blocked {
			continue
		}
		if !best.IsValid() || (ip.Is4() && !best.Is4()) {
			best = ip
		}
	}
	if !best.IsValid() {
		best = ips[0].Unmap()
	}
	return netip.AddrPortFrom(best, uint16(port)), nil
}

// dialDNS ignores the system resolver address and uses Bimeron's servers.
func (c *Client) dialDNS(ctx context.Context, network, _ string) (net.Conn, error) {
	var last error = errResolve
	for _, server := range c.dns {
		var conn net.Conn
		var err error
		if strings.HasPrefix(network, "tcp") {
			conn, err = c.DialStream(ctx, server.String())
		} else {
			conn, err = c.dialUDP(ctx, server)
		}
		if err == nil {
			return conn, nil
		}
		last = err
	}
	return nil, last
}

// dialUDP returns a connected datagram conn to one destination.
func (c *Client) dialUDP(ctx context.Context, to netip.AddrPort) (net.Conn, error) {
	pc, err := c.ListenPacket(ctx)
	if err != nil {
		return nil, err
	}
	return &connectedPacket{PacketConn: pc, to: net.UDPAddrFromAddrPort(to)}, nil
}

// ListenPacket returns an unconnected socket whose datagrams are routed per
// destination: into the tunnel, direct, or dropped.
func (c *Client) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	if c.isClosed() {
		return nil, ErrClosed
	}
	return newScopedPacket(c), nil
}

// connectedPacket adapts a PacketConn to net.Conn for the Go resolver.
type connectedPacket struct {
	net.PacketConn
	to *net.UDPAddr
}

func (p *connectedPacket) Read(b []byte) (int, error) {
	for {
		n, from, err := p.ReadFrom(b)
		if err != nil {
			return n, err
		}
		if u, ok := from.(*net.UDPAddr); ok && u.AddrPort() == p.to.AddrPort() {
			return n, nil
		}
	}
}
func (p *connectedPacket) Write(b []byte) (int, error) { return p.WriteTo(b, p.to) }
func (p *connectedPacket) RemoteAddr() net.Addr        { return p.to }
