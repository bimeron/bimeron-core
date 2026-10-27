package tuic

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

type packet struct {
	data []byte
	from net.Addr
}

type packetConn struct {
	owner                       *Client
	conn                        *quic.Conn
	id                          uint16
	ctx                         context.Context
	cancel                      context.CancelFunc
	incoming                    chan packet
	mu                          sync.Mutex
	closed                      bool
	packetID                    uint16
	readDeadline, writeDeadline time.Time
	changed                     chan struct{}
	fragments                   map[uint16]*fragmentedPacket
}

type fragmentedPacket struct {
	from        net.Addr
	parts       [][]byte
	count, size int
	created     time.Time
}

func (p *packetConn) accept(id uint16, total, index byte, from net.Addr, data []byte) {
	if total == 0 || index >= total || (index == 0) != (from != nil) {
		return
	}
	if total == 1 {
		select {
		case p.incoming <- packet{data: data, from: from}:
		case <-p.ctx.Done():
		default:
		}
		return
	}
	p.mu.Lock()
	if p.fragments == nil {
		p.fragments = make(map[uint16]*fragmentedPacket)
	}
	for key, f := range p.fragments {
		if time.Since(f.created) > 10*time.Second {
			delete(p.fragments, key)
		}
	}
	f := p.fragments[id]
	if f == nil {
		if len(p.fragments) >= 64 {
			p.mu.Unlock()
			return
		}
		f = &fragmentedPacket{parts: make([][]byte, int(total)), created: time.Now()}
		p.fragments[id] = f
	}
	if len(f.parts) != int(total) || f.parts[index] != nil || f.size+len(data) > 65535 {
		delete(p.fragments, id)
		p.mu.Unlock()
		return
	}
	f.parts[index] = data
	f.count++
	f.size += len(data)
	if index == 0 {
		f.from = from
	}
	if f.count != len(f.parts) {
		p.mu.Unlock()
		return
	}
	assembled := make([]byte, 0, f.size)
	for _, part := range f.parts {
		assembled = append(assembled, part...)
	}
	delete(p.fragments, id)
	p.mu.Unlock()
	if f.from == nil {
		return
	}
	select {
	case p.incoming <- packet{data: assembled, from: f.from}:
	case <-p.ctx.Done():
	default:
	}
}

func (p *packetConn) WriteTo(data []byte, address net.Addr) (int, error) {
	if address == nil || len(data) > 65535 {
		return 0, fmt.Errorf("invalid TUIC datagram")
	}
	encoded, err := addressBytes(address.String())
	if err != nil {
		return 0, err
	}
	p.mu.Lock()
	if p.closed || p.ctx.Err() != nil {
		p.mu.Unlock()
		return 0, net.ErrClosed
	}
	deadline := p.writeDeadline
	p.packetID++
	id := p.packetID
	p.mu.Unlock()
	ctx := p.ctx
	var cancel context.CancelFunc
	if !deadline.IsZero() {
		ctx, cancel = context.WithDeadline(ctx, deadline)
		defer cancel()
	}
	stream, err := p.conn.OpenUniStreamSync(ctx)
	if err != nil {
		return 0, err
	}
	frame := []byte{version, 2}
	frame = binary.BigEndian.AppendUint16(frame, p.id)
	frame = binary.BigEndian.AppendUint16(frame, id)
	frame = append(frame, 1, 0)
	frame = binary.BigEndian.AppendUint16(frame, uint16(len(data)))
	frame = append(frame, encoded...)
	frame = append(frame, data...)
	if !deadline.IsZero() {
		_ = stream.SetWriteDeadline(deadline)
	}
	for len(frame) > 0 {
		n, writeErr := stream.Write(frame)
		if writeErr != nil {
			stream.CancelWrite(0)
			return 0, writeErr
		}
		if n == 0 {
			stream.CancelWrite(0)
			return 0, os.ErrDeadlineExceeded
		}
		frame = frame[n:]
	}
	if err := stream.Close(); err != nil {
		return 0, err
	}
	return len(data), nil
}

func (p *packetConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		p.mu.Lock()
		deadline, changed := p.readDeadline, p.changed
		p.mu.Unlock()
		var timeout <-chan time.Time
		var timer *time.Timer
		if !deadline.IsZero() {
			if !time.Now().Before(deadline) {
				return 0, nil, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(time.Until(deadline))
			timeout = timer.C
		}
		select {
		case pkt := <-p.incoming:
			if timer != nil {
				timer.Stop()
			}
			if len(pkt.data) > len(b) {
				return 0, nil, fmt.Errorf("TUIC datagram exceeds buffer")
			}
			return copy(b, pkt.data), pkt.from, nil
		case <-p.ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return 0, nil, net.ErrClosed
		case <-changed:
			if timer != nil {
				timer.Stop()
			}
		case <-timeout:
			return 0, nil, os.ErrDeadlineExceeded
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
	p.mu.Unlock()
	p.owner.mu.Lock()
	if p.owner.packets[p.id] == p {
		delete(p.owner.packets, p.id)
	}
	p.owner.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	stream, err := p.conn.OpenUniStreamSync(ctx)
	if err == nil {
		frame := binary.BigEndian.AppendUint16([]byte{version, 3}, p.id)
		_, _ = stream.Write(frame)
		_ = stream.Close()
	}
	return nil
}

func (p *packetConn) LocalAddr() net.Addr { return packetAddr("0.0.0.0:0") }
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
