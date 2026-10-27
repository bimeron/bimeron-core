package vmess

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

type datagram struct {
	data []byte
	from net.Addr
}
type packetSession struct {
	conn *streamConn
	mu   sync.Mutex
}
type packetConn struct {
	owner                       *Client
	ctx                         context.Context
	cancel                      context.CancelFunc
	mu                          sync.Mutex
	sessions                    map[string]*packetSession
	incoming                    chan datagram
	fail                        chan error
	changed                     chan struct{}
	readDeadline, writeDeadline time.Time
	closed                      bool
}

func (c *Client) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	owned, cancel := context.WithCancel(ctx)
	p := &packetConn{owner: c, ctx: owned, cancel: cancel, sessions: make(map[string]*packetSession), incoming: make(chan datagram, 64), fail: make(chan error, 1), changed: make(chan struct{})}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		cancel()
		return nil, net.ErrClosed
	}
	c.packets[p] = struct{}{}
	c.mu.Unlock()
	context.AfterFunc(owned, func() { _ = p.Close() })
	return p, nil
}

func (p *packetConn) WriteTo(b []byte, address net.Addr) (int, error) {
	if address == nil || len(b) == 0 || len(b) > 8192-82 {
		return 0, fmt.Errorf("invalid VMess datagram")
	}
	key := address.String()
	if _, err := encodeAddress(key); err != nil {
		return 0, err
	}
	p.mu.Lock()
	if p.closed || p.ctx.Err() != nil {
		p.mu.Unlock()
		return 0, net.ErrClosed
	}
	s := p.sessions[key]
	deadline := p.writeDeadline
	p.mu.Unlock()
	if s == nil {
		openCtx := p.ctx
		cancel := func() {}
		if !deadline.IsZero() {
			openCtx, cancel = context.WithDeadline(p.ctx, deadline)
		}
		conn, err := p.owner.open(openCtx, 2, key)
		cancel()
		if err != nil {
			return 0, err
		}
		candidate := &packetSession{conn: conn}
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			_ = conn.Close()
			return 0, net.ErrClosed
		}
		if s = p.sessions[key]; s == nil {
			if len(p.sessions) >= 32 {
				p.mu.Unlock()
				_ = conn.Close()
				return 0, fmt.Errorf("too many VMess destinations")
			}
			s = candidate
			p.sessions[key] = s
			go p.readSession(key, s, address)
		} else {
			_ = conn.Close()
		}
		p.mu.Unlock()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.conn.SetWriteDeadline(deadline)
	if _, err := s.conn.Write(b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (p *packetConn) readSession(key string, s *packetSession, from net.Addr) {
	defer s.conn.Close()
	for {
		frame, err := s.conn.readPacket()
		if err != nil {
			p.mu.Lock()
			if p.sessions[key] == s {
				delete(p.sessions, key)
			}
			empty := len(p.sessions) == 0
			p.mu.Unlock()
			if p.ctx.Err() == nil && empty {
				select {
				case p.fail <- err:
				default:
				}
			}
			return
		}
		select {
		case p.incoming <- datagram{frame, from}:
		case <-p.ctx.Done():
			return
		}
	}
}

func (s *streamConn) readPacket() ([]byte, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	s.readOnce.Do(func() { s.readErr = readResponseHeader(s.Conn, s.responseKey, s.responseIV, s.expected) })
	if s.readErr != nil {
		return nil, s.readErr
	}
	return s.reader.readFrame()
}

func (p *packetConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		if p.ctx.Err() != nil {
			return 0, nil, net.ErrClosed
		}
		p.mu.Lock()
		deadline, changed := p.readDeadline, p.changed
		p.mu.Unlock()
		var timer *time.Timer
		var timeout <-chan time.Time
		if !deadline.IsZero() {
			if !time.Now().Before(deadline) {
				return 0, nil, &net.OpError{Op: "read", Net: "udp", Err: os.ErrDeadlineExceeded}
			}
			timer = time.NewTimer(time.Until(deadline))
			timeout = timer.C
		}
		select {
		case packet := <-p.incoming:
			if timer != nil {
				timer.Stop()
			}
			if len(packet.data) > len(b) {
				return 0, nil, fmt.Errorf("VMess datagram exceeds buffer")
			}
			return copy(b, packet.data), packet.from, nil
		case err := <-p.fail:
			if timer != nil {
				timer.Stop()
			}
			return 0, nil, err
		case <-changed:
			if timer != nil {
				timer.Stop()
			}
		case <-timeout:
			return 0, nil, &net.OpError{Op: "read", Net: "udp", Err: os.ErrDeadlineExceeded}
		case <-p.ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return 0, nil, net.ErrClosed
		}
	}
}

func (p *packetConn) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	p.cancel()
	sessions := make([]*packetSession, 0, len(p.sessions))
	for _, s := range p.sessions {
		sessions = append(sessions, s)
	}
	p.mu.Unlock()
	for _, s := range sessions {
		_ = s.conn.Close()
	}
	p.owner.mu.Lock()
	delete(p.owner.packets, p)
	p.owner.mu.Unlock()
	return nil
}
func (p *packetConn) LocalAddr() net.Addr { return &net.UDPAddr{IP: net.IPv4zero} }
func (p *packetConn) SetDeadline(t time.Time) error {
	p.mu.Lock()
	p.readDeadline = t
	p.writeDeadline = t
	close(p.changed)
	p.changed = make(chan struct{})
	p.mu.Unlock()
	return nil
}
func (p *packetConn) SetReadDeadline(t time.Time) error {
	p.mu.Lock()
	p.readDeadline = t
	close(p.changed)
	p.changed = make(chan struct{})
	p.mu.Unlock()
	return nil
}
func (p *packetConn) SetWriteDeadline(t time.Time) error {
	p.mu.Lock()
	p.writeDeadline = t
	p.mu.Unlock()
	return nil
}
