// SPDX-License-Identifier: MPL-2.0
// XUDP framing adapted from Xray-core common/xudp/xudp.go v1.260327.0.
// Modified for Bimeron's transport interfaces. One stream is used per destination.
package vless

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

const maxPacket = 8192 // Xray's common/buf.Size at the pinned protocol version.

type datagram struct {
	data []byte
	from net.Addr
}
type packetSession struct {
	conn   *streamConn
	target net.Addr
	mu     sync.Mutex
	first  bool
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

func xudpFrame(target string, payload []byte, first bool) ([]byte, error) {
	if len(payload) == 0 || len(payload) > maxPacket-666 {
		return nil, errors.New("invalid XUDP packet size")
	}
	meta := []byte{0, 0}
	if first {
		address, err := addressBytes(target)
		if err != nil {
			return nil, err
		}
		meta = append(meta, 1, 1, 2)
		meta = append(meta, address...)
	} else {
		meta = append(meta, 2, 1)
	}
	b := binary.BigEndian.AppendUint16(nil, uint16(len(meta)))
	b = append(b, meta...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(payload)))
	return append(b, payload...), nil
}

func (p *packetConn) WriteTo(b []byte, address net.Addr) (int, error) {
	if address == nil {
		return 0, errors.New("missing XUDP destination")
	}
	key := address.String()
	encoded, err := addressBytes(key)
	if err != nil {
		return 0, err
	}
	if len(encoded) >= 2 && binary.BigEndian.Uint16(encoded[:2]) == 443 && p.owner.settings.Flow != "xtls-rprx-vision-udp443" {
		return 0, errors.New("Vision requires explicit udp443 flow for UDP/443")
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
		conn, err := p.owner.open(openCtx, 3, "v1.mux.cool:666")
		cancel()
		if err != nil {
			return 0, err
		}
		candidate := &packetSession{conn: conn, target: address, first: true}
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
				return 0, errors.New("too many XUDP destinations")
			}
			s = candidate
			p.sessions[key] = s
			go p.readSession(key, s)
		} else {
			_ = conn.Close()
		}
		p.mu.Unlock()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	frame, err := xudpFrame(key, b, s.first)
	if err != nil {
		return 0, err
	}
	_ = s.conn.SetWriteDeadline(deadline)
	if _, err = s.conn.Write(frame); err != nil {
		return 0, err
	}
	s.first = false
	return len(b), nil
}

func xudpRead(r io.Reader, fallback net.Addr) (datagram, error) {
	for {
		var size [2]byte
		if _, err := io.ReadFull(r, size[:]); err != nil {
			return datagram{}, err
		}
		length := int(binary.BigEndian.Uint16(size[:]))
		if length < 4 || length > 512 {
			return datagram{}, errors.New("invalid XUDP metadata")
		}
		meta := make([]byte, length)
		if _, err := io.ReadFull(r, meta); err != nil {
			return datagram{}, err
		}
		if meta[2] != 2 && meta[2] != 4 {
			return datagram{}, errors.New("invalid XUDP command")
		}
		from := fallback
		if len(meta) > 5 && meta[4] == 2 {
			if address, err := readAddress(meta[5:]); err == nil {
				from = address
			}
		}
		if meta[3] != 1 {
			continue
		}
		if _, err := io.ReadFull(r, size[:]); err != nil {
			return datagram{}, err
		}
		length = int(binary.BigEndian.Uint16(size[:]))
		if length <= 0 || length > maxPacket {
			return datagram{}, errors.New("invalid XUDP payload")
		}
		data := make([]byte, length)
		if _, err := io.ReadFull(r, data); err != nil {
			return datagram{}, err
		}
		if meta[2] == 4 {
			continue
		}
		return datagram{data, from}, nil
	}
}

func readAddress(b []byte) (net.Addr, error) {
	if len(b) < 3 {
		return nil, errors.New("invalid XUDP address")
	}
	port := int(binary.BigEndian.Uint16(b[:2]))
	switch b[2] {
	case 1:
		if len(b) < 7 {
			break
		}
		return &net.UDPAddr{IP: net.IP(append([]byte(nil), b[3:7]...)), Port: port}, nil
	case 3:
		if len(b) < 19 {
			break
		}
		return &net.UDPAddr{IP: net.IP(append([]byte(nil), b[3:19]...)), Port: port}, nil
	}
	return nil, errors.New("invalid XUDP address")
}

func (p *packetConn) readSession(key string, s *packetSession) {
	defer s.conn.Close()
	defer func() {
		p.mu.Lock()
		if p.sessions[key] == s {
			delete(p.sessions, key)
		}
		p.mu.Unlock()
	}()
	for {
		packet, err := xudpRead(s.conn, s.target)
		if err != nil {
			p.mu.Lock()
			if p.sessions[key] == s {
				delete(p.sessions, key)
			}
			empty := len(p.sessions) == 0
			p.mu.Unlock()
			if empty {
				select {
				case p.fail <- err:
				default:
				}
			}
			return
		}
		select {
		case p.incoming <- packet:
		case <-p.ctx.Done():
			return
		}
	}
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
			return copy(b, packet.data), packet.from, nil
		case err := <-p.fail:
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
			return 0, nil, &net.OpError{Op: "read", Net: "udp", Err: os.ErrDeadlineExceeded}
		case <-changed:
			if timer != nil {
				timer.Stop()
			}
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
	for _, s := range p.sessions {
		_ = s.conn.Close()
	}
	p.mu.Unlock()
	p.owner.mu.Lock()
	delete(p.owner.packets, p)
	p.owner.mu.Unlock()
	return nil
}
func (p *packetConn) LocalAddr() net.Addr { return &net.UDPAddr{IP: net.IPv4zero} }
func (p *packetConn) SetDeadline(t time.Time) error {
	p.mu.Lock()
	p.readDeadline, p.writeDeadline = t, t
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
