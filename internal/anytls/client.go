package anytls

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"bimeron/internal/accesskey"
	"bimeron/internal/streamtransport"
	"golang.getoutline.org/sdk/transport"
)

type Client struct {
	profile accesskey.Profile
	dialer  net.Dialer
	rootCAs *x509.CertPool
	mu      sync.Mutex
	padding padScheme
	idle    []*session
	active  map[*session]struct{}
	closed  bool
	stop    chan struct{}
}

type session struct {
	conn      net.Conn
	owner     *Client
	scheme    padScheme
	writeMu   sync.Mutex
	streamMu  sync.Mutex
	stream    *stream
	done      chan struct{}
	doneOnce  sync.Once
	packet    int
	nextID    uint32
	idleSince time.Time
	closed    bool
}

type stream struct {
	session  *session
	id       uint32
	incoming chan received
	readMu   sync.Mutex
	pending  []byte
	readEnd  bool
	writeMu  sync.Mutex
	writeEnd bool
	closeMu  sync.Mutex
	closed   bool
}

type received struct {
	data []byte
	err  error
}

var _ transport.StreamDialer = (*Client)(nil)
var _ transport.PacketListener = (*Client)(nil)
var _ transport.StreamConn = (*stream)(nil)

func New(profile accesskey.Profile, dialer net.Dialer) (*Client, error) {
	if profile.Type != "anytls" {
		return nil, fmt.Errorf("expected AnyTLS profile")
	}
	if err := profile.AnyTLS.Validate(profile.TCP.Host, profile.TCP.Port); err != nil {
		return nil, err
	}
	padding, err := parsePadding(defaultPadding)
	if err != nil {
		return nil, err
	}
	c := &Client{profile: profile, dialer: dialer, padding: padding, active: make(map[*session]struct{}), stop: make(chan struct{})}
	go c.reapIdle()
	return c, nil
}

func (c *Client) reapIdle() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			c.mu.Lock()
			var keep []*session
			for _, s := range c.idle {
				if time.Since(s.idleSince) >= 60*time.Second {
					s.closed = true
					delete(c.active, s)
					s.doneOnce.Do(func() { close(s.done) })
					_ = s.conn.Close()
				} else {
					keep = append(keep, s)
				}
			}
			c.idle = keep
			c.mu.Unlock()
		case <-c.stop:
			return
		}
	}
}

func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	close(c.stop)
	for s := range c.active {
		s.closed = true
		s.doneOnce.Do(func() { close(s.done) })
		_ = s.conn.Close()
	}
	c.active = nil
	c.idle = nil
	c.mu.Unlock()
	return nil
}

func (c *Client) newSession(ctx context.Context) (*session, error) {
	setup, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	endpoint := net.JoinHostPort(c.profile.TCP.Host, strconv.Itoa(c.profile.TCP.Port))
	raw, err := c.dialer.DialContext(setup, "tcp", endpoint)
	if err != nil {
		return nil, fmt.Errorf("AnyTLS connection failed: %w", err)
	}
	conn, err := streamtransport.TLS(setup, raw, c.profile.AnyTLS.ServerName, nil, "", c.rootCAs)
	if err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("AnyTLS TLS failed: %w", err)
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		_ = conn.Close()
		return nil, net.ErrClosed
	}
	scheme := c.padding
	s := &session{conn: conn, owner: c, scheme: scheme, done: make(chan struct{})}
	c.active[s] = struct{}{}
	c.mu.Unlock()
	password := sha256.Sum256([]byte(c.profile.AnyTLS.Password))
	pad, err := padSize(scheme.steps[0][0])
	if err != nil {
		s.discard()
		return nil, fmt.Errorf("AnyTLS padding unavailable")
	}
	auth := make([]byte, 34+pad)
	copy(auth, password[:])
	binary.BigEndian.PutUint16(auth[32:34], uint16(pad))
	_ = conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
	err = writeAll(conn, auth)
	_ = conn.SetWriteDeadline(time.Time{})
	if err != nil {
		s.discard()
		return nil, fmt.Errorf("AnyTLS authentication write failed")
	}
	go s.readLoop()
	return s, nil
}

func (c *Client) acquire(ctx context.Context) (*session, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, net.ErrClosed
	}
	for len(c.idle) != 0 {
		last := len(c.idle) - 1
		s := c.idle[last]
		c.idle = c.idle[:last]
		if !s.closed && time.Since(s.idleSince) < 60*time.Second {
			c.mu.Unlock()
			return s, nil
		}
		s.closed = true
		delete(c.active, s)
		s.doneOnce.Do(func() { close(s.done) })
		_ = s.conn.Close()
	}
	c.mu.Unlock()
	return c.newSession(ctx)
}

func (s *session) discard() {
	c := s.owner
	c.mu.Lock()
	if !s.closed {
		s.closed = true
		delete(c.active, s)
		s.doneOnce.Do(func() { close(s.done) })
		_ = s.conn.Close()
	}
	c.mu.Unlock()
}

func (s *session) release() {
	c := s.owner
	_ = s.conn.SetDeadline(time.Time{})
	s.streamMu.Lock()
	s.stream = nil
	s.streamMu.Unlock()
	c.mu.Lock()
	if !s.closed && !c.closed {
		s.idleSince = time.Now()
		c.idle = append(c.idle, s)
	} else if !s.closed {
		s.closed = true
		delete(c.active, s)
		s.doneOnce.Do(func() { close(s.done) })
		_ = s.conn.Close()
	}
	c.mu.Unlock()
}

func (c *Client) open(ctx context.Context, target string) (*stream, error) {
	address, err := socksAddress(target)
	if err != nil {
		return nil, err
	}
	s, err := c.acquire(ctx)
	if err != nil {
		return nil, err
	}
	s.nextID++
	id := s.nextID
	stream := &stream{session: s, id: id, incoming: make(chan received, 16)}
	s.streamMu.Lock()
	s.stream = stream
	s.streamMu.Unlock()
	var payload []byte
	if id == 1 {
		hash := md5.Sum([]byte(s.scheme.text))
		settings := []byte("v=2\nclient=bimeron-core/dev\npadding-md5=" + hex.EncodeToString(hash[:]))
		payload = append(payload, frame(cmdSettings, 0, settings)...)
	}
	payload = append(payload, frame(cmdSYN, id, nil)...)
	payload = append(payload, frame(cmdPSH, id, address)...)
	stop := context.AfterFunc(ctx, s.discard)
	defer stop()
	_ = s.conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
	defer s.conn.SetWriteDeadline(time.Time{})
	if err := s.writePayload(payload); err != nil {
		s.discard()
		return nil, fmt.Errorf("AnyTLS stream open failed")
	}
	return stream, nil
}

func (c *Client) DialStream(ctx context.Context, target string) (transport.StreamConn, error) {
	return c.open(ctx, target)
}

func (s *session) writePayload(payload []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	steps := s.scheme.steps[s.packet+1]
	if s.packet+1 >= s.scheme.stop {
		steps = nil
	}
	s.packet++
	for _, step := range steps {
		size, err := padSize(step)
		if err != nil {
			return err
		}
		if size == 0 {
			continue
		}
		count := min(len(payload), size)
		record := append([]byte(nil), payload[:count]...)
		payload = payload[count:]
		if len(record)+7 <= size {
			record = append(record, frame(cmdWaste, 0, make([]byte, size-len(record)-7))...)
		} else if len(record) == 0 {
			record = frame(cmdWaste, 0, nil)
		}
		if err := writeAll(s.conn, record); err != nil {
			return err
		}
		if len(payload) == 0 && step.check {
			return nil
		}
	}
	for len(payload) != 0 {
		n := min(len(payload), 16384)
		if err := writeAll(s.conn, payload[:n]); err != nil {
			return err
		}
		payload = payload[n:]
	}
	return nil
}

func writeAll(w io.Writer, b []byte) error {
	for len(b) != 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}

func (s *session) readLoop() {
	defer s.discard()
	for {
		command, streamID, data, err := readFrame(s.conn)
		if err != nil {
			return
		}
		switch command {
		case cmdWaste, cmdServerSettings:
			continue
		case cmdHeartRequest:
			if err := s.writePayload(frame(cmdHeartResponse, 0, nil)); err != nil {
				return
			}
		case cmdUpdatePadding:
			scheme, err := parsePadding(string(data))
			if err != nil {
				return
			}
			s.owner.mu.Lock()
			s.owner.padding = scheme
			s.owner.mu.Unlock()
		case cmdSYNACK:
			if len(data) != 0 && !s.deliver(streamID, received{err: fmt.Errorf("AnyTLS upstream rejected stream")}) {
				return
			}
		case cmdPSH:
			if !s.deliver(streamID, received{data: data}) {
				return
			}
		case cmdFIN:
			if !s.deliver(streamID, received{err: io.EOF}) {
				return
			}
		case cmdAlert:
			return
		default:
			return
		}
	}
}

func (s *session) deliver(id uint32, message received) bool {
	s.streamMu.Lock()
	stream := s.stream
	s.streamMu.Unlock()
	if stream == nil || stream.id != id {
		return false
	}
	select {
	case stream.incoming <- message:
		return true
	case <-s.done:
		return false
	}
}
