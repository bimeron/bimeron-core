package wireguard

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"syscall"
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
	// direct connections for destinations outside AllowedIPs. Its Control
	// or ControlContext hook must keep those sockets out of the tunnel.
	Outbound net.Dialer
	// DNS lists resolver IPs (port 53) for names given to DialStream. The
	// queries follow the same scope as other traffic.
	DNS []string
}

// Client is one WireGuard device generation. It is safe for concurrent use.
// Close ends every socket and stream the generation opened, including
// direct ones outside the tunnel.
type Client struct {
	tunnel    tunnel
	bind      *Bind
	outbound  net.Dialer
	control   func(network, address string, c syscall.RawConn) error
	endpoint  netip.AddrPort
	fixedPort bool
	allowed   []netip.Prefix
	families  [2]bool // local tunnel address families: [IPv4, IPv6]
	mode      string
	guardV6   bool
	dns       []netip.AddrPort
	closed    chan struct{}
	once      sync.Once
	mu        sync.Mutex
	owned     map[io.Closer]struct{}
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
// WaitHandshake before reporting the session as connected. Errors are
// ErrPlatformLimit, ErrSocket or a generic engine failure.
func New(o Options) (*Client, error) {
	return newWithEngine(o, startAWG)
}

// listenControl adapts the dialer's socket hook to net.ListenConfig, with
// ControlContext taking precedence as it does for net.Dialer.
func listenControl(d net.Dialer) func(network, address string, c syscall.RawConn) error {
	if d.ControlContext != nil {
		return func(network, address string, c syscall.RawConn) error {
			return d.ControlContext(context.Background(), network, address, c)
		}
	}
	return d.Control
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
	endpoint := netip.AddrPortFrom(o.Endpoint.Addr().Unmap(), o.Endpoint.Port())
	client := &Client{
		outbound:  o.Outbound,
		control:   listenControl(o.Outbound),
		endpoint:  endpoint,
		fixedPort: c.ListenPort != 0,
		allowed:   allowed,
		mode:      mode,
		guardV6:   wgconf.Summarize(allowed).Coverage == wgconf.CoverageIPv4Only,
		closed:    make(chan struct{}),
		owned:     map[io.Closer]struct{}{},
	}
	for _, a := range c.LocalAddresses() {
		client.families[boolIndex(a.Is6())] = true
	}
	for _, s := range o.DNS {
		if a, err := netip.ParseAddr(s); err == nil {
			client.dns = append(client.dns, netip.AddrPortFrom(a.Unmap(), 53))
		}
	}
	lc := net.ListenConfig{Control: client.control}
	client.bind = NewBind(lc.ListenPacket, endpoint)
	handshake, transportSize, junk, signature := c.PacketSizes()
	t, err := start(tunnelConfig{
		Addresses: c.LocalAddresses(),
		MTU:       c.TunnelMTU(),
		UAPI:      c.UAPI(endpoint, peerAllowed),
		PublicKey: c.Peer.PublicKey,
		Bind:      client.bind,
		Sizes:     [4]int{handshake, transportSize, junk, signature},
	})
	if err != nil {
		if errors.Is(err, ErrPlatformLimit) || errors.Is(err, ErrSocket) {
			return nil, err
		}
		return nil, errEngine
	}
	client.tunnel = t
	return client, nil
}

func boolIndex(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Endpoint is the physical peer address this generation uses.
func (c *Client) Endpoint() netip.AddrPort { return c.endpoint }

// ExclusivePort reports a fixed ListenPort: a replacement generation can
// open its socket only after this one is closed.
func (c *Client) ExclusivePort() bool { return c.fixedPort }

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

// WaitHandshake waits for the first handshake of this generation. A new
// device has none, so any completed handshake counts, including one that
// a persistent keepalive started before the wait began.
func (c *Client) WaitHandshake(ctx context.Context) error {
	return c.waitHandshakeAfter(ctx, time.Time{})
}

// waitHandshakeAfter starts a handshake and waits until the reported time
// differs from previous. Comparing for change, not order, tolerates wall
// clock adjustments.
func (c *Client) waitHandshakeAfter(ctx context.Context, previous time.Time) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	nudge := time.Now()
	c.tunnel.Initiate()
	for {
		if last := c.tunnel.LastHandshake(); !last.IsZero() && !last.Equal(previous) {
			return nil
		}
		select {
		case <-ctx.Done():
			return errHandshake
		case <-c.closed:
			return ErrClosed
		case now := <-ticker.C:
			// The engine retries on its own; a periodic nudge covers a
			// dropped initiation.
			if now.Sub(nudge) >= 5*time.Second {
				nudge = now
				c.tunnel.Initiate()
			}
		}
	}
}

// LastHandshake reports the most recent completed handshake.
func (c *Client) LastHandshake() time.Time { return c.tunnel.LastHandshake() }

// probeFreshness is how recent a handshake must be for Probe to pass
// without a new one.
const probeFreshness = 150 * time.Second

// Probe checks that the peer still answers. A recent handshake is enough;
// otherwise it forces a new one and waits for it to complete.
func (c *Client) Probe(ctx context.Context) error {
	last := c.tunnel.LastHandshake()
	if age := time.Since(last); !last.IsZero() && age >= 0 && age < probeFreshness {
		return nil
	}
	return c.waitHandshakeAfter(ctx, last)
}

// Traffic reports encrypted bytes on the wire.
func (c *Client) Traffic() (sent, received uint64) { return c.bind.Traffic() }

// own registers a resource of this generation. It fails after Close.
func (c *Client) own(r io.Closer) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.isClosed() {
		return false
	}
	c.owned[r] = struct{}{}
	return true
}

func (c *Client) disown(r io.Closer) {
	c.mu.Lock()
	delete(c.owned, r)
	c.mu.Unlock()
}

// Close stops the device and closes every socket and stream it opened.
func (c *Client) Close() error {
	c.once.Do(func() {
		c.mu.Lock()
		close(c.closed)
		owned := c.owned
		c.owned = map[io.Closer]struct{}{}
		c.mu.Unlock()
		for r := range owned {
			_ = r.Close()
		}
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

// ownedTCP closes itself from the generation's resource set.
type ownedTCP struct {
	*net.TCPConn
	client *Client
}

func (t *ownedTCP) Close() error {
	t.client.disown(t)
	return t.TCPConn.Close()
}

// DialStream connects to an IP or name. Names are resolved through the
// configured resolvers, routed by scope; usable answers are tried in order.
func (c *Client) DialStream(ctx context.Context, address string) (transport.StreamConn, error) {
	if c.isClosed() {
		return nil, ErrClosed
	}
	candidates, err := c.resolve(ctx, address)
	if err != nil {
		return nil, err
	}
	last := error(ErrBlocked)
	for _, to := range candidates {
		stream, err := c.dialOne(ctx, to)
		if err == nil {
			return stream, nil
		}
		last = err
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, last
}

func (c *Client) dialOne(ctx context.Context, to netip.AddrPort) (transport.StreamConn, error) {
	switch c.scope(to.Addr()) {
	case blocked:
		return nil, ErrBlocked
	case viaDirect:
		conn, err := c.outbound.DialContext(ctx, "tcp", to.String())
		if err != nil {
			return nil, err
		}
		tcp, ok := conn.(*net.TCPConn)
		if !ok {
			_ = conn.Close()
			return nil, errTunnel
		}
		owned := &ownedTCP{TCPConn: tcp, client: c}
		if !c.own(owned) {
			_ = tcp.Close()
			return nil, ErrClosed
		}
		return owned, nil
	}
	if !c.families[boolIndex(to.Addr().Is6())] {
		// The tunnel has no address of this family.
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

// resolve returns the destinations to try: the IP itself, or the answers
// for a name that the scope permits and the tunnel can reach, IPv4 first.
func (c *Client) resolve(ctx context.Context, address string) ([]netip.AddrPort, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return nil, errors.New("invalid port")
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.AddrPort{netip.AddrPortFrom(ip.Unmap(), uint16(port))}, nil
	}
	ips, err := c.lookup(ctx, host)
	if err != nil {
		return nil, err
	}
	var v4, v6 []netip.AddrPort
	for _, ip := range ips {
		ip = ip.Unmap()
		switch c.scope(ip) {
		case blocked:
			continue
		case viaTunnel:
			if !c.families[boolIndex(ip.Is6())] {
				continue
			}
		}
		if ip.Is4() {
			v4 = append(v4, netip.AddrPortFrom(ip, uint16(port)))
		} else {
			v6 = append(v6, netip.AddrPortFrom(ip, uint16(port)))
		}
	}
	if len(v4)+len(v6) == 0 {
		return nil, ErrBlocked
	}
	return append(v4, v6...), nil
}

// ListenPacket returns an unconnected socket whose datagrams are routed per
// destination: into the tunnel, direct, or dropped.
func (c *Client) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	p := newScopedPacket(c)
	if !c.own(p) {
		return nil, ErrClosed
	}
	return p, nil
}
