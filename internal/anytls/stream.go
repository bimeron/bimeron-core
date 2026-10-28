package anytls

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

func (s *stream) Read(b []byte) (int, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	if len(b) == 0 {
		return 0, nil
	}
	if s.readEnd && len(s.pending) == 0 {
		return 0, io.EOF
	}
	for len(s.pending) == 0 {
		message := s.receive()
		if message.err != nil {
			if message.err == io.EOF {
				s.readEnd = true
			} else {
				if !errors.Is(message.err, os.ErrDeadlineExceeded) {
					s.session.discard()
				}
			}
			return 0, message.err
		}
		s.pending = message.data
	}
	n := copy(b, s.pending)
	s.pending = s.pending[n:]
	return n, nil
}

// Read deadlines belong to the logical stream, not the background control reader.
// They can be extended after a timeout without destroying the TLS session.
func (s *stream) receive() received {
	for {
		s.deadlineMu.Lock()
		if s.deadlineChanged == nil {
			s.deadlineChanged = make(chan struct{})
		}
		deadline, changed := s.readDeadline, s.deadlineChanged
		s.deadlineMu.Unlock()
		var timer *time.Timer
		var timeout <-chan time.Time
		if !deadline.IsZero() {
			if !time.Now().Before(deadline) {
				return received{err: os.ErrDeadlineExceeded}
			}
			timer = time.NewTimer(time.Until(deadline))
			timeout = timer.C
		}
		var result received
		select {
		case result = <-s.incoming:
		case <-s.session.done:
			// Preserve frames queued before the transport failed.
			select {
			case result = <-s.incoming:
			default:
				result.err = s.session.readError()
			}
		case <-timeout:
			result.err = os.ErrDeadlineExceeded
		case <-changed:
			if timer != nil {
				timer.Stop()
			}
			continue
		}
		if timer != nil {
			timer.Stop()
		}
		return result
	}
}

func (s *stream) Write(b []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.writeEnd {
		return 0, net.ErrClosed
	}
	written := 0
	for len(b) != 0 {
		n := min(len(b), 16384)
		if err := s.session.writePayload(frame(cmdPSH, s.id, b[:n])); err != nil {
			s.session.discard()
			return written, err
		}
		written += n
		b = b[n:]
	}
	return written, nil
}

func (s *stream) CloseWrite() error {
	// AnyTLS FIN closes the entire logical stream; it is not a TCP half-close.
	return s.Close()
}

func (s *stream) CloseRead() error {
	return s.Close()
}

func (s *stream) Close() error {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if !s.writeMu.TryLock() {
		s.session.discard()
		s.writeMu.Lock()
	}
	s.writeEnd = true
	s.writeMu.Unlock()
	if !s.readMu.TryLock() {
		s.session.discard()
		s.readMu.Lock()
	}
	readEnd := s.readEnd
	s.readMu.Unlock()
	if !readEnd {
		s.session.discard()
		return nil
	}
	s.session.release()
	return nil
}

func (s *stream) LocalAddr() net.Addr  { return s.session.conn.LocalAddr() }
func (s *stream) RemoteAddr() net.Addr { return s.session.conn.RemoteAddr() }
func (s *stream) SetDeadline(t time.Time) error {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	if s.closed {
		return net.ErrClosed
	}
	s.setReadDeadline(t)
	return s.session.conn.SetWriteDeadline(t)
}
func (s *stream) SetReadDeadline(t time.Time) error {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	if s.closed {
		return net.ErrClosed
	}
	s.setReadDeadline(t)
	return nil
}

func (s *stream) setReadDeadline(t time.Time) {
	s.deadlineMu.Lock()
	defer s.deadlineMu.Unlock()
	s.readDeadline = t
	if s.deadlineChanged != nil {
		close(s.deadlineChanged)
	}
	s.deadlineChanged = make(chan struct{})
}
func (s *stream) SetWriteDeadline(t time.Time) error {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	if s.closed {
		return net.ErrClosed
	}
	return s.session.conn.SetWriteDeadline(t)
}

type packetConn struct {
	stream  *stream
	readMu  sync.Mutex
	writeMu sync.Mutex
	stop    func() bool
	mu      sync.Mutex
}

func (c *Client) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	s, err := c.open(ctx, "sp.v2.udp-over-tcp.arpa:0")
	if err != nil {
		return nil, err
	}
	// UDP-over-TCP v2's request starts with isConnect=0 and a SOCKS address.
	request := []byte{0, 1, 0, 0, 0, 0, 0, 0}
	stopSetup := context.AfterFunc(ctx, func() { _ = s.Close() })
	_ = s.SetWriteDeadline(time.Now().Add(15 * time.Second))
	_, err = s.Write(request)
	stopSetup()
	_ = s.SetWriteDeadline(time.Time{})
	if err != nil || ctx.Err() != nil {
		_ = s.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	p := &packetConn{stream: s}
	stop := context.AfterFunc(ctx, func() { _ = p.Close() })
	p.mu.Lock()
	p.stop = stop
	p.mu.Unlock()
	return p, nil
}

func (p *packetConn) ReadFrom(b []byte) (int, net.Addr, error) {
	p.readMu.Lock()
	defer p.readMu.Unlock()
	addr, err := readUoTAddress(p.stream)
	if err != nil {
		return 0, nil, err
	}
	var size [2]byte
	if _, err := io.ReadFull(p.stream, size[:]); err != nil {
		return 0, nil, err
	}
	n := int(binary.BigEndian.Uint16(size[:]))
	if n > len(b) {
		_, _ = io.CopyN(io.Discard, p.stream, int64(n))
		return 0, nil, io.ErrShortBuffer
	}
	_, err = io.ReadFull(p.stream, b[:n])
	return n, addr, err
}

func (p *packetConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	if len(b) > 65535 {
		return 0, fmt.Errorf("AnyTLS UDP packet too large")
	}
	address, err := uotAddress(addr)
	if err != nil {
		return 0, err
	}
	request := binary.BigEndian.AppendUint16(address, uint16(len(b)))
	request = append(request, b...)
	if _, err := p.stream.Write(request); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (p *packetConn) Close() error {
	p.mu.Lock()
	if p.stop != nil {
		p.stop()
		p.stop = nil
	}
	p.mu.Unlock()
	return p.stream.Close()
}

func (p *packetConn) LocalAddr() net.Addr                { return packetAddress("0.0.0.0:0") }
func (p *packetConn) SetDeadline(t time.Time) error      { return p.stream.SetDeadline(t) }
func (p *packetConn) SetReadDeadline(t time.Time) error  { return p.stream.SetReadDeadline(t) }
func (p *packetConn) SetWriteDeadline(t time.Time) error { return p.stream.SetWriteDeadline(t) }
