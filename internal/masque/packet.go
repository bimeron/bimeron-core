package masque

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

const maxDestinations = 32
const idleTimeout = 60 * time.Second

type datagram struct {
	data []byte
	from net.Addr
}
type tunnel struct {
	stream *streamConn
	target net.Addr
	used   time.Time
}
type packetConn struct {
	owner                       *Client
	ctx                         context.Context
	cancel                      context.CancelFunc
	stop                        func() bool
	mu                          sync.Mutex
	closed                      bool
	done                        chan struct{}
	sessions                    map[string]*tunnel
	incoming                    chan datagram
	failures                    chan error
	changed                     chan struct{}
	readDeadline, writeDeadline time.Time
	writes                      chan struct{}
	wg                          sync.WaitGroup
}

func (c *Client) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.ctx.Err() != nil || ctx.Err() != nil {
		return nil, net.ErrClosed
	}
	if len(c.packets) >= 128 {
		return nil, fmt.Errorf("MASQUE packet listener limit reached")
	}
	owned, cancel := context.WithCancel(ctx)
	p := &packetConn{owner: c, ctx: owned, cancel: cancel, sessions: make(map[string]*tunnel), incoming: make(chan datagram, 64), failures: make(chan error, 1), changed: make(chan struct{}), writes: make(chan struct{}, 1), done: make(chan struct{})}
	c.packets[p] = struct{}{}
	// Register while holding p.mu so even an already-cancelled ctx cannot race stop.
	p.wg.Add(1)
	p.mu.Lock()
	p.stop = context.AfterFunc(owned, func() { _ = p.Close() })
	p.mu.Unlock()
	go p.reap()
	return p, nil
}

// writeContext follows deadline changes even while opening a tunnel or waiting
// for a concurrent writer. Deadlines never apply to the shared QUIC connection.
func (p *packetConn) writeContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(p.ctx)
	go func() {
		for {
			p.mu.Lock()
			deadline, changed := p.writeDeadline, p.changed
			p.mu.Unlock()
			var timer *time.Timer
			var timeout <-chan time.Time
			if !deadline.IsZero() {
				if !time.Now().Before(deadline) {
					cancel()
					return
				}
				timer = time.NewTimer(time.Until(deadline))
				timeout = timer.C
			}
			select {
			case <-ctx.Done():
				if timer != nil {
					timer.Stop()
				}
				return
			case <-timeout:
				cancel()
				return
			case <-changed:
				if timer != nil {
					timer.Stop()
				}
			}
		}
	}()
	return ctx, cancel
}

func (p *packetConn) writeError(ctx context.Context, err error) error {
	if p.ctx.Err() != nil {
		return net.ErrClosed
	}
	if ctx.Err() != nil {
		return os.ErrDeadlineExceeded
	}
	return err
}

func (p *packetConn) WriteTo(b []byte, address net.Addr) (int, error) {
	if address == nil || len(b) > maxPayload {
		return 0, fmt.Errorf("invalid or oversized MASQUE datagram (maximum 1500 bytes)")
	}
	target := address.String()
	if err := validTarget(target); err != nil {
		return 0, err
	}
	ctx, cancel := p.writeContext()
	defer cancel()
	select {
	case p.writes <- struct{}{}:
	case <-ctx.Done():
		return 0, p.writeError(ctx, ctx.Err())
	}
	defer func() { <-p.writes }()
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return 0, net.ErrClosed
	}
	deadline := p.writeDeadline
	session := p.sessions[target]
	full := len(p.sessions) >= maxDestinations
	p.mu.Unlock()
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return 0, os.ErrDeadlineExceeded
	}
	if err := ctx.Err(); err != nil {
		return 0, p.writeError(ctx, err)
	}
	if session == nil {
		if full {
			return 0, fmt.Errorf("MASQUE destination limit reached")
		}
		stream, err := p.owner.open(ctx, target, true)
		if err != nil {
			return 0, p.writeError(ctx, err)
		}
		session = &tunnel{stream: stream, target: packetAddr(target), used: time.Now()}
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			stream.abort()
			return 0, net.ErrClosed
		}
		p.sessions[target] = session
		p.wg.Add(2)
		p.mu.Unlock()
		go p.receive(target, session)
		go p.capsules(session)
	}
	p.mu.Lock()
	session.used = time.Now()
	deadline = p.writeDeadline
	p.mu.Unlock()
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return 0, os.ErrDeadlineExceeded
	}
	if err := ctx.Err(); err != nil {
		return 0, p.writeError(ctx, err)
	}
	frame := append([]byte{0}, b...)
	if err := p.owner.sendDatagram(ctx, session.stream, frame); err != nil {
		return 0, p.writeError(ctx, err)
	}
	return len(b), nil
}

func (p *packetConn) capsules(s *tunnel) {
	defer p.wg.Done()
	defer s.stream.abort()
	parser := http3.NewCapsuleParser(s.stream)
	for {
		_, value, err := parser.Next()
		if err != nil {
			return
		}
		// No capsule extensions are negotiated by this profile. Discard without
		// allocating from the peer-provided length, as required by RFC 9297.
		if err := value.Discard(); err != nil {
			return
		}
	}
}

func (p *packetConn) receive(key string, s *tunnel) {
	defer p.wg.Done()
	defer s.stream.abort()
	for {
		data, err := s.stream.ReceiveDatagram(p.ctx)
		if err != nil {
			p.mu.Lock()
			report := !p.closed && p.sessions[key] == s
			if p.sessions[key] == s {
				delete(p.sessions, key)
			}
			p.mu.Unlock()
			if report {
				select {
				case p.failures <- &net.OpError{Op: "read", Net: "udp", Addr: s.target, Err: tunnelClosedError{}}:
				default:
				}
			}
			return
		}
		id, n, err := quicvarint.Parse(data)
		if err != nil || id != 0 || len(data)-n > maxPayload {
			continue
		}
		p.mu.Lock()
		s.used = time.Now()
		p.mu.Unlock()
		// DATAGRAM is deliberately lossy. A slow reader must not block other flows.
		select {
		case p.incoming <- datagram{data: data[n:], from: s.target}:
		default:
		}
	}
}

func (p *packetConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		p.mu.Lock()
		deadline, changed, closed := p.readDeadline, p.changed, p.closed
		p.mu.Unlock()
		if closed || p.ctx.Err() != nil {
			return 0, nil, net.ErrClosed
		}
		var timer *time.Timer
		var timeout <-chan time.Time
		if !deadline.IsZero() {
			if !time.Now().Before(deadline) {
				return 0, nil, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(time.Until(deadline))
			timeout = timer.C
		}
		select {
		case d := <-p.incoming:
			if timer != nil {
				timer.Stop()
			}
			if len(d.data) > len(b) {
				return 0, d.from, io.ErrShortBuffer
			}
			return copy(b, d.data), d.from, nil
		case err := <-p.failures:
			if timer != nil {
				timer.Stop()
			}
			return 0, nil, err
		case <-p.ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return 0, nil, net.ErrClosed
		case <-timeout:
			return 0, nil, os.ErrDeadlineExceeded
		case <-changed:
			if timer != nil {
				timer.Stop()
			}
		}
	}
}

func (p *packetConn) reap() {
	defer p.wg.Done()
	ticker := time.NewTicker(idleTimeout / 2)
	defer ticker.Stop()
	for {
		select {
		case <-p.ctx.Done():
			return
		case now := <-ticker.C:
			p.expire(now)
		}
	}
}
func (p *packetConn) expire(now time.Time) {
	var expired []*tunnel
	p.mu.Lock()
	for key, s := range p.sessions {
		if now.Sub(s.used) >= idleTimeout {
			delete(p.sessions, key)
			expired = append(expired, s)
		}
	}
	p.mu.Unlock()
	for _, s := range expired {
		s.stream.abort()
	}
}

func (p *packetConn) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		<-p.done
		return nil
	}
	p.closed = true
	p.stop()
	p.cancel()
	sessions := p.sessions
	p.sessions = make(map[string]*tunnel)
	p.mu.Unlock()
	for _, s := range sessions {
		s.stream.abort()
	}
	p.wg.Wait()
	p.owner.mu.Lock()
	delete(p.owner.packets, p)
	p.owner.mu.Unlock()
	close(p.done)
	return nil
}

type packetAddr string

func (a packetAddr) Network() string      { return "udp" }
func (a packetAddr) String() string       { return string(a) }
func (p *packetConn) LocalAddr() net.Addr { return packetAddr("0.0.0.0:0") }
func (p *packetConn) setDeadline(t time.Time, read, write bool) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return net.ErrClosed
	}
	if read {
		p.readDeadline = t
	}
	if write {
		p.writeDeadline = t
	}
	close(p.changed)
	p.changed = make(chan struct{})
	return nil
}
func (p *packetConn) SetDeadline(t time.Time) error      { return p.setDeadline(t, true, true) }
func (p *packetConn) SetReadDeadline(t time.Time) error  { return p.setDeadline(t, true, false) }
func (p *packetConn) SetWriteDeadline(t time.Time) error { return p.setDeadline(t, false, true) }

// quic-go's SendDatagram can block on its connection-wide queue and has no
// context API. One bounded worker owns that call; logical writes can time out
// independently without spawning a blocked goroutine for every timed-out write.
// A datagram already handed to QUIC cannot be withdrawn on a deadline race.
type datagramWrite struct {
	ctx    context.Context
	stream *streamConn
	data   []byte
	result chan error
}

func (c *Client) sendDatagram(ctx context.Context, stream *streamConn, data []byte) error {
	w := datagramWrite{ctx: ctx, stream: stream, data: data, result: make(chan error, 1)}
	select {
	case c.outgoing <- w:
	case <-ctx.Done():
		return ctx.Err()
	case <-c.ctx.Done():
		return net.ErrClosed
	}
	select {
	case err := <-w.result:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-c.ctx.Done():
		return net.ErrClosed
	}
}
func (c *Client) sendPackets() {
	defer close(c.senderDone)
	for {
		select {
		case <-c.ctx.Done():
			return
		case w := <-c.outgoing:
			if err := w.ctx.Err(); err != nil {
				w.result <- err
				continue
			}
			w.result <- w.stream.SendDatagram(w.data)
		}
	}
}

// A tunnel failure is scoped to one destination. The packet listener remains
// usable, and the next write to that destination can open a new tunnel.
type tunnelClosedError struct{}

func (tunnelClosedError) Error() string   { return "MASQUE UDP tunnel closed" }
func (tunnelClosedError) Timeout() bool   { return false }
func (tunnelClosedError) Temporary() bool { return true }
