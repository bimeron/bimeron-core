// Package v2raymux implements TCP sessions using the V2Ray Mux wire protocol.
package v2raymux

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"golang.getoutline.org/sdk/transport"
)

const (
	chunkSize   = 8 * 1024
	maxBuffered = 256 * 1024
	idleTimeout = 30 * time.Second
)

// Pool owns WebSocket byte streams. Each stream carries at most concurrency
// sessions; identifiers are never reused on a connection.
type Pool struct {
	endpoint    transport.StreamEndpoint
	concurrency uint32
	target      []byte
	mu          sync.Mutex
	workers     map[*worker]struct{}
	dialing     chan struct{}
	ctx         context.Context
	cancel      context.CancelFunc
}

func New(endpoint transport.StreamEndpoint, concurrency uint32, target string) (*Pool, error) {
	if endpoint == nil || concurrency == 0 {
		return nil, fmt.Errorf("invalid Mux endpoint or concurrency")
	}
	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("invalid Mux target")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 || host == "" {
		return nil, fmt.Errorf("invalid Mux target")
	}
	address := binary.BigEndian.AppendUint16([]byte{1}, uint16(port))
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			address = append(address, 1)
			address = append(address, v4...)
		} else {
			address = append(address, 3)
			address = append(address, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return nil, fmt.Errorf("invalid Mux target")
		}
		address = append(address, 2, byte(len(host)))
		address = append(address, host...)
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Pool{endpoint: endpoint, concurrency: concurrency, target: address, workers: make(map[*worker]struct{}), ctx: ctx, cancel: cancel}, nil
}

func (p *Pool) ConnectStream(ctx context.Context) (transport.StreamConn, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		p.mu.Lock()
		if p.ctx.Err() != nil {
			p.mu.Unlock()
			return nil, net.ErrClosed
		}
		for w := range p.workers {
			if w.next == 65535 || uint32(len(w.sessions)) >= p.concurrency {
				continue
			}
			w.next++
			s := &stream{worker: w, id: w.next, done: make(chan struct{}), changed: make(chan struct{})}
			s.ctx, s.cancel = context.WithCancel(context.Background())
			w.sessions[s.id] = s
			if w.idle != nil {
				w.idle.Stop()
				w.idle = nil
			}
			p.mu.Unlock()
			meta := append([]byte{byte(s.id >> 8), byte(s.id), 1, 0}, p.target...)
			deadline, _ := ctx.Deadline()
			if err := w.send(ctx, nil, deadline, meta, nil); err != nil {
				s.finish(err)
				return nil, err
			}
			return s, nil
		}
		if p.dialing != nil {
			wait := p.dialing
			p.mu.Unlock()
			select {
			case <-wait:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-p.ctx.Done():
				return nil, net.ErrClosed
			}
		}
		p.dialing = make(chan struct{})
		p.mu.Unlock()
		setup, cancel := context.WithTimeout(ctx, 15*time.Second)
		stop := context.AfterFunc(p.ctx, cancel)
		conn, err := p.endpoint.ConnectStream(setup)
		stop()
		cancel()
		p.mu.Lock()
		close(p.dialing)
		p.dialing = nil
		if err != nil || p.ctx.Err() != nil {
			closed := p.ctx.Err() != nil
			p.mu.Unlock()
			if conn != nil {
				_ = conn.Close()
			}
			if closed {
				return nil, net.ErrClosed
			}
			return nil, err
		}
		w := &worker{pool: p, conn: conn, sessions: make(map[uint16]*stream), token: make(chan struct{}, 1), done: make(chan struct{})}
		w.token <- struct{}{}
		p.workers[w] = struct{}{}
		p.mu.Unlock()
		go w.readLoop()
	}
}

func (p *Pool) Close() error {
	p.cancel()
	p.mu.Lock()
	workers := make([]*worker, 0, len(p.workers))
	for w := range p.workers {
		workers = append(workers, w)
	}
	p.mu.Unlock()
	for _, w := range workers {
		w.fail(net.ErrClosed)
	}
	return nil
}

type worker struct {
	pool *Pool
	conn transport.StreamConn
	// sessions, next, and idle are protected by pool.mu.
	sessions map[uint16]*stream
	next     uint16
	idle     *time.Timer
	token    chan struct{}
	done     chan struct{}
	once     sync.Once
}

func (w *worker) fail(err error) {
	w.once.Do(func() {
		close(w.done)
		_ = w.conn.Close()
		w.pool.mu.Lock()
		delete(w.pool.workers, w)
		if w.idle != nil {
			w.idle.Stop()
		}
		sessions := w.sessions
		w.sessions = make(map[uint16]*stream)
		w.pool.mu.Unlock()
		for _, s := range sessions {
			s.end(err)
		}
	})
}

func (w *worker) detach(s *stream) {
	w.pool.mu.Lock()
	delete(w.sessions, s.id)
	_, alive := w.pool.workers[w]
	if alive && len(w.sessions) == 0 {
		if w.next == 65535 {
			delete(w.pool.workers, w)
			w.pool.mu.Unlock()
			w.fail(net.ErrClosed)
			return
		}
		w.idle = time.AfterFunc(idleTimeout, func() {
			w.pool.mu.Lock()
			idle := len(w.sessions) == 0
			if idle {
				delete(w.pool.workers, w)
			}
			w.pool.mu.Unlock()
			if idle {
				w.fail(net.ErrClosed)
			}
		})
	}
	w.pool.mu.Unlock()
}

func waitDeadline(deadline time.Time) (<-chan time.Time, func()) {
	if deadline.IsZero() {
		return nil, func() {}
	}
	t := time.NewTimer(time.Until(deadline))
	return t.C, func() { t.Stop() }
}

// send serializes complete frames. A deadline while waiting for the writer
// affects only that session; a partial frame failure retires the connection.
func (w *worker) send(ctx context.Context, s *stream, deadline time.Time, meta, data []byte) error {
	if s == nil && deadline.IsZero() {
		deadline = time.Now().Add(15 * time.Second)
	}
	for {
		var done, changed <-chan struct{}
		if s != nil {
			s.mu.Lock()
			deadline, done, changed = s.writeDeadline, s.done, s.changed
			s.mu.Unlock()
		}
		timeout, stop := waitDeadline(deadline)
		acquired := false
		select {
		case <-ctx.Done():
			stop()
			return ctx.Err()
		case <-done:
			stop()
			return net.ErrClosed
		case <-w.done:
			stop()
			return net.ErrClosed
		case <-timeout:
			stop()
			return os.ErrDeadlineExceeded
		case <-changed:
		case <-w.token:
			acquired = true
		}
		stop()
		if acquired {
			break
		}
	}
	defer func() { w.token <- struct{}{} }()
	if err := ctx.Err(); err != nil {
		return err
	}
	if s != nil {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return net.ErrClosed
		}
		deadline = s.writeDeadline
		s.writing = true
		_ = w.conn.SetWriteDeadline(deadline)
		s.mu.Unlock()
		defer func() { s.mu.Lock(); s.writing = false; _ = w.conn.SetWriteDeadline(time.Time{}); s.mu.Unlock() }()
	} else {
		_ = w.conn.SetWriteDeadline(deadline)
		defer w.conn.SetWriteDeadline(time.Time{})
	}
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return os.ErrDeadlineExceeded
	}
	// Once a frame starts, cancellation or a partial-write timeout retires the
	// connection: another frame cannot safely continue a truncated byte stream.
	canceled := make(chan struct{})
	stopCancel := context.AfterFunc(ctx, func() { _ = w.conn.SetWriteDeadline(time.Now()); close(canceled) })
	stopSession := func() bool { return true }
	if s != nil {
		stopSession = context.AfterFunc(s.ctx, func() {
			s.mu.Lock()
			if s.writing {
				_ = w.conn.SetWriteDeadline(time.Now())
			}
			s.mu.Unlock()
		})
	}
	defer stopSession()
	frame := binary.BigEndian.AppendUint16(nil, uint16(len(meta)))
	frame = append(frame, meta...)
	if len(data) > 0 {
		frame = binary.BigEndian.AppendUint16(frame, uint16(len(data)))
		frame = append(frame, data...)
	}
	for len(frame) > 0 {
		n, err := w.conn.Write(frame)
		if err != nil || n == 0 {
			stopCancel()
			if err == nil {
				err = io.ErrShortWrite
			}
			w.fail(err)
			return err
		}
		frame = frame[n:]
	}
	if !stopCancel() {
		<-canceled // The cancellation callback must finish before another writer.
	}
	return nil
}

func (w *worker) readLoop() {
	for {
		if err := w.readFrame(); err != nil {
			w.fail(err)
			return
		}
	}
}

func (w *worker) readFrame() error {
	var length [2]byte
	if _, err := io.ReadFull(w.conn, length[:]); err != nil {
		return err
	}
	n := int(binary.BigEndian.Uint16(length[:]))
	if n < 4 || n > 512 {
		return fmt.Errorf("invalid Mux metadata length")
	}
	meta := make([]byte, n)
	if _, err := io.ReadFull(w.conn, meta); err != nil {
		return err
	}
	id, status, flags := binary.BigEndian.Uint16(meta[:2]), meta[2], meta[3]
	if status < 1 || status > 4 || flags & ^byte(3) != 0 || status == 1 || (status != 3 && flags&2 != 0) {
		return fmt.Errorf("invalid Mux response metadata")
	}
	var data []byte
	if flags&1 != 0 {
		if _, err := io.ReadFull(w.conn, length[:]); err != nil {
			return err
		}
		data = make([]byte, int(binary.BigEndian.Uint16(length[:])))
		if _, err := io.ReadFull(w.conn, data); err != nil {
			return err
		}
	}
	if status == 4 {
		return nil
	}
	w.pool.mu.Lock()
	s := w.sessions[id]
	allocated := id > 0 && id <= w.next
	w.pool.mu.Unlock()
	if !allocated {
		return fmt.Errorf("invalid Mux response session identifier")
	}
	if s == nil {
		return nil
	} // Frames already in flight for closed sessions are drained.
	if status == 3 {
		if flags&2 != 0 {
			s.finish(fmt.Errorf("Mux peer terminated session"))
		} else {
			s.finish(io.EOF)
		}
		return nil
	}
	if !s.deliver(data) {
		s.finish(fmt.Errorf("Mux session receive buffer exceeded"))
		// Keep a stalled stream from blocking the shared receive loop.
		go s.sendEnd()
	}
	return nil
}

type stream struct {
	worker                      *worker
	id                          uint16
	writeMu                     sync.Mutex
	mu                          sync.Mutex
	buffer                      bytes.Buffer
	closed                      bool
	writing                     bool
	ctx                         context.Context
	cancel                      context.CancelFunc
	err                         error
	done                        chan struct{}
	changed                     chan struct{}
	readDeadline, writeDeadline time.Time
}

func (s *stream) signal() { close(s.changed); s.changed = make(chan struct{}) }
func (s *stream) end(err error) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.closed, s.err = true, err
	s.cancel()
	close(s.done)
	s.signal()
	return true
}
func (s *stream) finish(err error) {
	if s.end(err) {
		s.worker.detach(s)
	}
}
func (s *stream) deliver(data []byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return true
	}
	if len(data)+s.buffer.Len() > maxBuffered {
		return false
	}
	s.buffer.Write(data)
	s.signal()
	return true
}
func (s *stream) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	for {
		s.mu.Lock()
		if !s.readDeadline.IsZero() && !time.Now().Before(s.readDeadline) {
			s.mu.Unlock()
			return 0, os.ErrDeadlineExceeded
		}
		if s.buffer.Len() > 0 {
			n, _ := s.buffer.Read(b)
			s.mu.Unlock()
			return n, nil
		}
		if s.closed {
			err := s.err
			s.mu.Unlock()
			return 0, err
		}
		changed, deadline := s.changed, s.readDeadline
		s.mu.Unlock()
		timeout, stop := waitDeadline(deadline)
		select {
		case <-changed:
		case <-timeout:
		}
		stop()
	}
}
func (s *stream) Write(b []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return 0, net.ErrClosed
	}
	written := 0
	for len(b) > 0 {
		n := min(len(b), chunkSize)
		meta := []byte{byte(s.id >> 8), byte(s.id), 2, 1}
		if err := s.worker.send(context.Background(), s, time.Time{}, meta, b[:n]); err != nil {
			return written, err
		}
		written += n
		b = b[n:]
	}
	return written, nil
}
func (s *stream) sendEnd() {
	_ = s.worker.send(context.Background(), nil, time.Now().Add(2*time.Second), []byte{byte(s.id >> 8), byte(s.id), 3, 0}, nil)
}
func (s *stream) Close() error {
	if s.end(net.ErrClosed) {
		s.sendEnd()
		s.worker.detach(s)
	}
	return nil
}
func (s *stream) CloseRead() error     { return s.Close() }
func (s *stream) CloseWrite() error    { return s.Close() }
func (s *stream) LocalAddr() net.Addr  { return s.worker.conn.LocalAddr() }
func (s *stream) RemoteAddr() net.Addr { return s.worker.conn.RemoteAddr() }
func (s *stream) SetDeadline(t time.Time) error {
	s.mu.Lock()
	s.readDeadline, s.writeDeadline = t, t
	if s.writing {
		_ = s.worker.conn.SetWriteDeadline(t)
	}
	s.signal()
	s.mu.Unlock()
	return nil
}
func (s *stream) SetReadDeadline(t time.Time) error {
	s.mu.Lock()
	s.readDeadline = t
	s.signal()
	s.mu.Unlock()
	return nil
}
func (s *stream) SetWriteDeadline(t time.Time) error {
	s.mu.Lock()
	s.writeDeadline = t
	if s.writing {
		_ = s.worker.conn.SetWriteDeadline(t)
	}
	s.signal()
	s.mu.Unlock()
	return nil
}
