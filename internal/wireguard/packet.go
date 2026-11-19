package wireguard

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"
)

// maxQueued bounds received datagrams waiting for ReadFrom.
const maxQueued = 64

// maxTunnelPeers bounds tunnel destinations of one packet socket. The VPN
// handler uses one destination per flow and DNS a few.
const maxTunnelPeers = 64

var errTooManyPeers = errors.New("too many WireGuard UDP destinations on one socket")

type datagram struct {
	data []byte
	from net.Addr
}

// scopedPacket routes datagrams per destination: tunnel destinations get a
// connected netstack socket each, direct ones share one outbound socket per
// family. Replies are merged into one bounded queue.
type scopedPacket struct {
	client   *Client
	mu       sync.Mutex
	tunnel   map[netip.AddrPort]net.Conn
	direct   map[bool]net.PacketConn
	incoming chan datagram
	closed   chan struct{}
	done     bool
	once     sync.Once
	wg       sync.WaitGroup
	deadline time.Time
	wake     chan struct{}
}

func newScopedPacket(c *Client) *scopedPacket {
	return &scopedPacket{client: c, tunnel: map[netip.AddrPort]net.Conn{}, direct: map[bool]net.PacketConn{}, incoming: make(chan datagram, maxQueued), closed: make(chan struct{}), wake: make(chan struct{}, 1)}
}

func (p *scopedPacket) tunnelSocket(to netip.AddrPort) (net.Conn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.done {
		return nil, net.ErrClosed
	}
	if s := p.tunnel[to]; s != nil {
		return s, nil
	}
	if len(p.tunnel) >= maxTunnelPeers {
		return nil, errTooManyPeers
	}
	s, err := p.client.tunnel.DialUDP(to)
	if err != nil {
		return nil, errTunnel
	}
	p.tunnel[to] = s
	from := net.UDPAddrFromAddrPort(to)
	p.wg.Add(1)
	go p.pump(func(b []byte) (int, net.Addr, error) { n, err := s.Read(b); return n, from, err })
	return s, nil
}

func (p *scopedPacket) directSocket(v6 bool) (net.PacketConn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.done {
		return nil, net.ErrClosed
	}
	if s := p.direct[v6]; s != nil {
		return s, nil
	}
	network, local := "udp4", "0.0.0.0:0"
	if v6 {
		network, local = "udp6", "[::]:0"
	}
	lc := net.ListenConfig{Control: p.client.outbound.Control}
	s, err := lc.ListenPacket(context.Background(), network, local)
	if err != nil {
		return nil, err
	}
	p.direct[v6] = s
	p.wg.Add(1)
	go p.pump(s.ReadFrom)
	return s, nil
}

// pump copies datagrams from one socket into the shared queue. When the queue
// is full the datagram is dropped, as a congested network would.
func (p *scopedPacket) pump(read func([]byte) (int, net.Addr, error)) {
	defer p.wg.Done()
	buf := make([]byte, 65535)
	for {
		n, from, err := read(buf)
		if err != nil {
			return
		}
		d := datagram{data: append([]byte(nil), buf[:n]...), from: from}
		select {
		case p.incoming <- d:
		case <-p.closed:
			return
		default:
		}
	}
}

func (p *scopedPacket) WriteTo(b []byte, addr net.Addr) (int, error) {
	u, ok := addr.(*net.UDPAddr)
	if !ok {
		resolved, err := net.ResolveUDPAddr("udp", addr.String())
		if err != nil {
			return 0, err
		}
		u = resolved
	}
	to := u.AddrPort()
	to = netip.AddrPortFrom(to.Addr().Unmap(), to.Port())
	switch p.client.scope(to.Addr()) {
	case blocked:
		// Dropped like a filtered datagram.
		return len(b), nil
	case viaDirect:
		s, err := p.directSocket(to.Addr().Is6())
		if err != nil {
			return 0, err
		}
		return s.WriteTo(b, net.UDPAddrFromAddrPort(to))
	}
	s, err := p.tunnelSocket(to)
	if err != nil {
		return 0, err
	}
	return s.Write(b)
}

func (p *scopedPacket) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		p.mu.Lock()
		deadline := p.deadline
		p.mu.Unlock()
		var timer *time.Timer
		var expired <-chan time.Time
		if !deadline.IsZero() {
			wait := time.Until(deadline)
			if wait <= 0 {
				return 0, nil, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(wait)
			expired = timer.C
		}
		var (
			d    datagram
			got  bool
			err  error
			wake bool
		)
		select {
		case d = <-p.incoming:
			got = true
		case <-p.closed:
			err = net.ErrClosed
		case <-p.client.closed:
			err = net.ErrClosed
		case <-expired:
			err = os.ErrDeadlineExceeded
		case <-p.wake:
			wake = true
		}
		if timer != nil {
			timer.Stop()
		}
		switch {
		case got:
			return copy(b, d.data), d.from, nil
		case err != nil:
			return 0, nil, err
		case wake:
			// The deadline changed; evaluate it again.
		}
	}
}

func (p *scopedPacket) Close() error {
	p.once.Do(func() {
		p.mu.Lock()
		p.done = true
		close(p.closed)
		for _, s := range p.tunnel {
			_ = s.Close()
		}
		for _, s := range p.direct {
			_ = s.Close()
		}
		p.mu.Unlock()
		p.wg.Wait()
	})
	return nil
}

func (p *scopedPacket) LocalAddr() net.Addr { return &net.UDPAddr{} }

func (p *scopedPacket) SetDeadline(t time.Time) error {
	_ = p.SetWriteDeadline(t)
	return p.SetReadDeadline(t)
}

func (p *scopedPacket) SetReadDeadline(t time.Time) error {
	p.mu.Lock()
	p.deadline = t
	p.mu.Unlock()
	select {
	case p.wake <- struct{}{}:
	default:
	}
	return nil
}

func (p *scopedPacket) SetWriteDeadline(t time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	var err error
	for _, s := range p.tunnel {
		err = errors.Join(err, s.SetWriteDeadline(t))
	}
	for _, s := range p.direct {
		err = errors.Join(err, s.SetWriteDeadline(t))
	}
	return err
}
