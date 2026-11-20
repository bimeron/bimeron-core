package tuic

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"bimeron/internal/accesskey"
	"bimeron/internal/guard"
	"github.com/quic-go/quic-go"
	"golang.getoutline.org/sdk/transport"
)

type Client struct {
	profile accesskey.Profile
	dialer  net.Dialer
	rootCAs *x509.CertPool
	// ctx is canceled by Close so an in-flight connect is aborted.
	ctx    context.Context
	cancel context.CancelFunc
	// connecting admits one connect at a time without holding mu during I/O.
	connecting chan struct{}
	mu         sync.Mutex
	current    *session
	sessions   map[*session]struct{}
	closed     bool
}

// Each QUIC connection owns a separate TUIC association ID space.
const associationIDs = 1 << 16

type session struct {
	conn        *quic.Conn
	socket      net.PacketConn
	packets     map[uint16]*packetConn
	nextID      uint32
	refs        int // TCP streams and UDP associations, including pending Dissociates
	dissociates chan uint16
}

var _ transport.StreamDialer = (*Client)(nil)
var _ transport.PacketListener = (*Client)(nil)

func New(profile accesskey.Profile, dialer net.Dialer) (*Client, error) {
	if profile.Type != "tuic" {
		return nil, fmt.Errorf("expected TUIC profile")
	}
	if err := profile.TUIC.Validate(profile.TCP.Host, profile.TCP.Port); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Client{profile: profile, dialer: dialer, ctx: ctx, cancel: cancel, connecting: make(chan struct{}, 1), sessions: make(map[*session]struct{})}, nil
}

func (c *Client) acquire(ctx context.Context, udp bool) (*session, uint16, error) {
	// Client closure takes precedence over setup cancellation during admission.
	if c.ctx.Err() != nil {
		return nil, 0, net.ErrClosed
	}
	select {
	case c.connecting <- struct{}{}:
	case <-c.ctx.Done():
		return nil, 0, net.ErrClosed
	case <-ctx.Done():
		return nil, 0, ctx.Err()
	}
	defer func() { <-c.connecting }()
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, 0, net.ErrClosed
	}
	if current := c.current; current != nil && current.conn.Context().Err() == nil && (!udp || current.nextID < associationIDs) {
		id := current.reserve(udp)
		c.mu.Unlock()
		return current, id, nil
	}
	c.mu.Unlock()
	// Network I/O below runs without mu; Close cancels it through c.ctx.
	ctx, stop := context.WithCancel(ctx)
	defer stop()
	defer context.AfterFunc(c.ctx, stop)()
	resolver := c.dialer.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	ips, err := resolver.LookupNetIP(ctx, "ip", c.profile.TCP.Host)
	if err != nil || len(ips) == 0 {
		return nil, 0, fmt.Errorf("TUIC endpoint resolution failed")
	}
	ip := ips[0]
	for _, candidate := range ips {
		if candidate.Unmap().Is4() {
			ip = candidate
			break
		}
	}
	ip = ip.Unmap()
	network, local := "udp4", "0.0.0.0:0"
	if ip.Is6() {
		network, local = "udp6", "[::]:0"
	}
	socket, err := (&net.ListenConfig{Control: c.dialer.Control}).ListenPacket(ctx, network, local)
	if err != nil {
		return nil, 0, fmt.Errorf("TUIC socket failed: %w", err)
	}
	remote := &net.UDPAddr{IP: net.IP(ip.AsSlice()), Port: c.profile.TCP.Port}
	tlsConfig := &tls.Config{ServerName: c.profile.TUIC.ServerName, NextProtos: []string{c.profile.TUIC.ALPN}, MinVersion: tls.VersionTLS13, RootCAs: c.rootCAs}
	setup, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	conn, err := quic.Dial(setup, socket, remote, tlsConfig, &quic.Config{EnableDatagrams: true, KeepAlivePeriod: 10 * time.Second})
	if err != nil {
		_ = socket.Close()
		return nil, 0, fmt.Errorf("TUIC QUIC connection failed: %w", err)
	}
	auth, err := conn.OpenUniStreamSync(setup)
	if err == nil {
		id := c.profile.TUIC.UUID()
		var token []byte
		state := conn.ConnectionState()
		token, err = state.TLS.ExportKeyingMaterial(string(id[:]), []byte(c.profile.TUIC.Password), 32)
		if err == nil {
			request := append([]byte{version, 0}, id[:]...)
			request = append(request, token...)
			err = writeAll(auth, request)
			if err == nil {
				err = auth.Close()
			}
		}
	}
	if err != nil {
		_ = conn.CloseWithError(0, "authentication failed")
		_ = socket.Close()
		return nil, 0, fmt.Errorf("TUIC authentication failed")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		_ = conn.CloseWithError(0, "closed")
		_ = socket.Close()
		return nil, 0, net.ErrClosed
	}
	old := c.current
	s := &session{conn: conn, socket: socket, packets: make(map[uint16]*packetConn),
		// Each issued ID can enter this queue only once, so Close never waits for credit.
		dissociates: make(chan uint16, associationIDs),
	}
	c.current = s
	c.sessions[s] = struct{}{}
	if old != nil && old.refs == 0 {
		_ = old.conn.CloseWithError(0, "drained")
	}
	guard.Go(func() { c.sendDissociates(s) })
	guard.Go(func() { c.readPackets(s) })
	guard.Go(func() { c.heartbeat(conn) })
	return s, s.reserve(udp), nil
}

// Called under the client mutex so rotation cannot race with admission.
func (s *session) reserve(udp bool) uint16 {
	s.refs++
	if udp {
		s.nextID++
	}
	return uint16(s.nextID)
}

func (c *Client) release(s *session) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s.refs--
	if s != c.current && s.refs == 0 {
		_ = s.conn.CloseWithError(0, "drained")
	}
}

func (c *Client) DialStream(ctx context.Context, target string) (transport.StreamConn, error) {
	address, err := addressBytes(target)
	if err != nil {
		return nil, err
	}
	s, _, err := c.acquire(ctx, false)
	if err != nil {
		return nil, err
	}
	conn := s.conn
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		c.release(s)
		return nil, err
	}
	if err := writeAll(stream, append([]byte{version, 1}, address...)); err != nil {
		stream.CancelRead(0)
		stream.CancelWrite(0)
		c.release(s)
		return nil, err
	}
	return &streamConn{release: func() { c.release(s) }, Stream: stream, local: conn.LocalAddr(), remote: conn.RemoteAddr()}, nil
}

func (c *Client) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	s, id, err := c.acquire(ctx, true)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || s.conn.Context().Err() != nil {
		s.refs--
		return nil, net.ErrClosed
	}
	pctx, cancel := context.WithCancel(ctx)
	p := &packetConn{owner: c, session: s, conn: s.conn, id: id, ctx: pctx, cancel: cancel, incoming: make(chan packet, 64), changed: make(chan struct{})}
	s.packets[id] = p
	return p, nil
}

func (c *Client) sendDissociates(s *session) {
	conn := s.conn
	defer func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		for _, p := range s.packets {
			p.cancel()
		}
		clear(s.packets)
		delete(c.sessions, s)
		if c.current == s {
			c.current = nil
		}
		_ = s.socket.Close()
	}()
	for {
		select {
		case <-conn.Context().Done():
			return
		case id := <-s.dissociates:
			stream, err := conn.OpenUniStreamSync(conn.Context())
			if err == nil {
				frame := binary.BigEndian.AppendUint16([]byte{version, 3}, id)
				err = writeAll(stream, frame)
				if err == nil {
					err = stream.Close()
				}
			}
			if err != nil {
				// Ending the session releases all associations at the peer.
				_ = conn.CloseWithError(1, "dissociation failed")
				return
			}
			// Close queues the FIN. Retain this connection until the peer's
			// transport acknowledges the frame, including during rotation.
			context.AfterFunc(stream.SendCompletionContext(), func() { c.release(s) })
		}
	}
}

func (c *Client) readPackets(s *session) {
	conn := s.conn
	for {
		stream, err := conn.AcceptUniStream(conn.Context())
		if err != nil {
			return
		}
		guard.Go(func() { c.readPacketStream(s, stream) })
	}
}

func (c *Client) readPacketStream(s *session, stream *quic.ReceiveStream) {
	defer stream.CancelRead(0)
	var header [10]byte
	if _, err := io.ReadFull(stream, header[:]); err != nil || header[0] != version || header[1] != 2 {
		return
	}
	id := binary.BigEndian.Uint16(header[2:4])
	packetID := binary.BigEndian.Uint16(header[4:6])
	size := int(binary.BigEndian.Uint16(header[8:10]))
	from, err := readAddress(stream)
	if err != nil {
		return
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(stream, data); err != nil {
		return
	}
	c.mu.Lock()
	p := s.packets[id]
	c.mu.Unlock()
	if p == nil {
		return
	}
	p.accept(packetID, header[6], header[7], from, data)
}

func (c *Client) heartbeat(conn *quic.Conn) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-conn.Context().Done():
			return
		case <-ticker.C:
			_ = conn.SendDatagram([]byte{version, 4})
		}
	}
}

func (c *Client) Close() error {
	c.cancel()
	c.mu.Lock()
	c.closed = true
	defer c.mu.Unlock()
	for s := range c.sessions {
		for _, p := range s.packets {
			p.cancel()
		}
		_ = s.conn.CloseWithError(0, "closed")
		_ = s.socket.Close()
	}
	return nil
}

// closeSendTimeout bounds how long Close waits for the peer to acknowledge
// buffered data and FIN before the send direction is reset.
const closeSendTimeout = 5 * time.Second

type streamConn struct {
	*quic.Stream
	release       func()
	local, remote net.Addr
	writeMu       sync.Mutex
	closed        atomic.Bool
	once          sync.Once
}

func (s *streamConn) LocalAddr() net.Addr  { return s.local }
func (s *streamConn) RemoteAddr() net.Addr { return s.remote }
func (s *streamConn) Read(b []byte) (int, error) {
	if s.closed.Load() {
		return 0, net.ErrClosed
	}
	n, err := s.Stream.Read(b)
	if s.closed.Load() {
		return n, net.ErrClosed
	}
	return n, err
}
func (s *streamConn) Write(b []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.closed.Load() {
		return 0, net.ErrClosed
	}
	return s.Stream.Write(b)
}

// Close finishes the send direction gracefully: buffered data and FIN stay
// eligible for retransmission until QUIC acknowledges them or
// closeSendTimeout expires. CancelWrite would discard that unacknowledged
// tail, truncating data the relay already reported as written.
func (s *streamConn) Close() error {
	s.once.Do(func() {
		s.closed.Store(true)
		// Interrupt public reads without sending STOP_SENDING before the peer
		// has had a chance to consume our payload and FIN.
		_ = s.Stream.SetReadDeadline(time.Now())
		if !s.writeMu.TryLock() {
			// Close must interrupt an in-progress flow-controlled Write.
			s.CancelRead(0)
			s.CancelWrite(0)
			s.release()
			return
		}
		_ = s.Stream.Close()
		s.writeMu.Unlock()
		go func() {
			defer guard.Recover()
			timer := time.NewTimer(closeSendTimeout)
			defer timer.Stop()
			select {
			case <-s.SendCompletionContext().Done():
			case <-timer.C:
				s.CancelWrite(0)
			}
			s.CancelRead(0)
			s.release()
		}()
	})
	return nil
}
func (s *streamConn) CloseRead() error { s.CancelRead(0); return nil }
func (s *streamConn) CloseWrite() error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.closed.Load() {
		return net.ErrClosed
	}
	return s.Stream.Close()
}

func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
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
