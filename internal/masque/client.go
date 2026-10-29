// Package masque implements the explicit RFC 9298 HTTP/3 datagram profile.
package masque

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"bimeron/internal/accesskey"
	"github.com/dunglas/httpsfv"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
	"golang.getoutline.org/sdk/transport"
)

const setupTimeout = 15 * time.Second
const maxTunnels = 256
const maxPayload = 1500
const closeSendTimeout = 5 * time.Second

type Client struct {
	profile     accesskey.Profile
	dialer      net.Dialer
	roots       *x509.CertPool
	template    *uritemplate.Template
	authority   string
	ctx         context.Context
	cancel      context.CancelFunc
	mu          sync.Mutex
	conn        *http3.ClientConn
	closed      bool
	packets     map[*packetConn]struct{}
	slots       chan struct{}
	connecting  chan struct{}
	outgoing    chan datagramWrite
	senderDone  chan struct{}
	generations map[*http3.ClientConn]*connectionGeneration
}

var _ transport.StreamDialer = (*Client)(nil)
var _ transport.PacketListener = (*Client)(nil)

func New(p accesskey.Profile, d net.Dialer) (*Client, error) {
	if p.Type != "masque" {
		return nil, fmt.Errorf("expected MASQUE profile")
	}
	if err := p.MASQUE.Validate(p.TCP.Host, p.TCP.Port, p.Username, p.TCP.Secret); err != nil {
		return nil, err
	}
	var roots *x509.CertPool
	if p.MASQUE.CAFile != "" {
		pem, err := os.ReadFile(p.MASQUE.CAFile)
		if err != nil {
			return nil, fmt.Errorf("could not read MASQUE CA file")
		}
		roots, err = x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("invalid MASQUE CA file")
		}
	}
	path := p.MASQUE.UDPPath
	if path == "" {
		path = accesskey.DefaultMASQUEPath
	}
	// Keep the logical authority and TLS name when bootstrap replaces the dial IP.
	proxyHost := p.MASQUE.ProxyHost
	if proxyHost == "" {
		proxyHost = p.TCP.Host
	}
	authority := net.JoinHostPort(proxyHost, strconv.Itoa(p.TCP.Port))
	template, err := uritemplate.New("https://" + authority + path)
	if err != nil {
		return nil, fmt.Errorf("invalid MASQUE URI template")
	}
	ctx, cancel := context.WithCancel(context.Background())
	c := &Client{profile: p, dialer: d, roots: roots, template: template, authority: authority, ctx: ctx, cancel: cancel, packets: make(map[*packetConn]struct{}), slots: make(chan struct{}, maxTunnels), connecting: make(chan struct{}, 1), outgoing: make(chan datagramWrite, 32), senderDone: make(chan struct{}), generations: make(map[*http3.ClientConn]*connectionGeneration)}
	go c.sendPackets()
	return c, nil
}

func (c *Client) connection(ctx context.Context) (*http3.ClientConn, error) {
	// Client closure takes precedence over setup cancellation during admission.
	if c.ctx.Err() != nil {
		return nil, net.ErrClosed
	}
	select {
	case c.connecting <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-c.connecting }()
	c.mu.Lock()
	if c.closed || c.ctx.Err() != nil {
		c.mu.Unlock()
		return nil, net.ErrClosed
	}
	if c.conn != nil && c.conn.Context().Err() == nil {
		conn := c.conn
		c.mu.Unlock()
		return conn, nil
	}
	dead := c.generations[c.conn]
	c.conn = nil
	c.mu.Unlock()
	if dead != nil {
		dead.close()
	}
	resolver := c.dialer.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	ips, err := resolver.LookupNetIP(ctx, "ip", c.profile.TCP.Host)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("MASQUE endpoint resolution failed")
	}
	ip := ips[0].Unmap()
	for _, candidate := range ips {
		if candidate.Unmap().Is4() {
			ip = candidate.Unmap()
			break
		}
	}
	network, local := "udp4", "0.0.0.0:0"
	if ip.Is6() {
		network, local = "udp6", "[::]:0"
	}
	socket, err := (&net.ListenConfig{Control: c.dialer.Control}).ListenPacket(ctx, network, local)
	if err != nil {
		return nil, fmt.Errorf("MASQUE socket failed")
	}
	qt := &quic.Transport{Conn: socket}
	qconn, err := qt.Dial(ctx, &net.UDPAddr{IP: net.IP(ip.AsSlice()), Port: c.profile.TCP.Port}, &tls.Config{ServerName: c.profile.MASQUE.ServerName, RootCAs: c.roots, MinVersion: tls.VersionTLS13, NextProtos: []string{http3.NextProtoH3}}, &quic.Config{EnableDatagrams: true, KeepAlivePeriod: 10 * time.Second})
	if err != nil {
		_ = qt.Close()
		_ = socket.Close()
		return nil, fmt.Errorf("MASQUE QUIC/TLS connection failed: %w", err)
	}
	h3 := &http3.Transport{EnableDatagrams: true, DisableCompression: true, GoAwayCloseDelay: closeSendTimeout, MaxResponseHeaderBytes: 16 * 1024}
	conn := h3.NewClientConn(qconn)
	var capabilityErr error
	select {
	case <-ctx.Done():
		capabilityErr = ctx.Err()
	case <-conn.Context().Done():
		capabilityErr = fmt.Errorf("MASQUE HTTP/3 connection closed during settings negotiation")
	case <-conn.ReceivedSettings():
		settings := conn.Settings()
		if !settings.EnableExtendedConnect || !settings.EnableDatagrams || !qconn.ConnectionState().SupportsDatagrams.Remote {
			capabilityErr = fmt.Errorf("MASQUE server requires Extended CONNECT, HTTP Datagrams and QUIC DATAGRAM")
		}
	}
	if capabilityErr != nil {
		_ = qconn.CloseWithError(0, "unsupported MASQUE profile")
		_ = qt.Close()
		_ = socket.Close()
		return nil, capabilityErr
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.ctx.Err() != nil {
		_ = qconn.CloseWithError(0, "closed")
		_ = qt.Close()
		_ = socket.Close()
		return nil, net.ErrClosed
	}
	c.conn = conn
	generation := &connectionGeneration{quicConn: qconn, qt: qt, socket: socket}
	c.generations[conn] = generation
	context.AfterFunc(conn.Context(), func() {
		generation.close()
		c.mu.Lock()
		delete(c.generations, conn)
		c.mu.Unlock()
	})
	return c.conn, nil
}

// A draining generation stays alive until its existing tunnels finish. Its
// socket and transport are released on connection closure or Client.Close.
type connectionGeneration struct {
	quicConn *quic.Conn
	qt       *quic.Transport
	socket   net.PacketConn
	once     sync.Once
}

func (g *connectionGeneration) close() {
	g.once.Do(func() {
		_ = g.quicConn.CloseWithError(0, "closed")
		_ = g.qt.Close()
		_ = g.socket.Close()
	})
}

func (c *Client) retire(conn *http3.ClientConn) {
	c.mu.Lock()
	if c.conn == conn {
		c.conn = nil
	}
	c.mu.Unlock()
}
func (c *Client) requestStream(ctx context.Context) (*http3.ClientConn, *http3.RequestStream, error) {
	for attempt := 0; ; attempt++ {
		conn, err := c.connection(ctx)
		if err != nil {
			return nil, nil, err
		}
		stream, err := conn.OpenRequestStream(ctx)
		if err == nil {
			return conn, stream, nil
		}
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		// OpenRequestStream reports GOAWAY with an unexported quic-go error. Retry
		// only this pre-request operation, once: no CONNECT headers or UDP payloads
		// have been sent, and existing streams on the draining connection survive.
		c.retire(conn)
		if attempt == 1 {
			return nil, nil, err
		}
	}
}

func validTarget(target string) error {
	host, port, err := net.SplitHostPort(target)
	if err != nil || host == "" || strings.ContainsAny(host, " /\\?#%\r\n\t") {
		return fmt.Errorf("invalid MASQUE destination")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("invalid MASQUE destination port")
	}
	return nil
}

func (c *Client) open(ctx context.Context, target string, udp bool) (*streamConn, error) {
	if err := validTarget(target); err != nil {
		return nil, err
	}
	select {
	case c.slots <- struct{}{}:
	default:
		return nil, fmt.Errorf("MASQUE tunnel limit reached")
	}
	var once sync.Once
	release := func() { once.Do(func() { <-c.slots }) }
	keep := false
	defer func() {
		if !keep {
			release()
		}
	}()
	setup, cancel := context.WithTimeout(ctx, setupTimeout)
	defer cancel()
	stopClient := context.AfterFunc(c.ctx, cancel)
	defer stopClient()
	req := &http.Request{Method: http.MethodConnect, URL: &url.URL{Scheme: "https", Host: target}, Host: target, Header: make(http.Header)}
	if udp {
		host, port, _ := net.SplitHostPort(target)
		expanded, err := c.template.Expand(uritemplate.Values{"target_host": uritemplate.String(host), "target_port": uritemplate.String(port)})
		if err != nil {
			return nil, fmt.Errorf("MASQUE URI expansion failed")
		}
		req.URL, err = url.Parse(expanded)
		if err != nil {
			return nil, fmt.Errorf("invalid MASQUE request URI")
		}
		req.Host, req.Proto = c.authority, "connect-udp"
		req.Header.Set(http3.CapsuleProtocolHeader, "?1")
	}
	if c.profile.Username != "" {
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(c.profile.Username+":"+c.profile.TCP.Secret)))
	}
	conn, str, err := c.requestStream(setup)
	if err != nil {
		return nil, err
	}
	stream := &streamConn{RequestStream: str, local: conn.LocalAddr(), remote: conn.RemoteAddr(), release: release, readMu: make(chan struct{}, 1), done: make(chan struct{})}
	// quic-go's low-level request stream doesn't bind response reads to ctx.
	// Explicit cancellation closes only this tunnel, preserving other streams.
	done := make(chan struct{})
	stop := context.AfterFunc(setup, func() { stream.abort(); close(done) })
	var stopOnce sync.Once
	finishSetup := func() {
		stopOnce.Do(func() {
			if !stop() {
				<-done
			}
		})
	}
	defer func() {
		finishSetup()
		if !keep {
			stream.abort()
		}
	}()
	deadline, _ := setup.Deadline()
	_ = str.SetDeadline(deadline)
	if err = str.SendRequestHeader(req); err != nil {
		return nil, err
	}
	response, err := str.ReadResponse()
	if err != nil {
		return nil, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, statusError(response.StatusCode)
	}
	if udp {
		item, err := httpsfv.UnmarshalItem(response.Header.Values(http3.CapsuleProtocolHeader))
		if err != nil || item.Value != true {
			return nil, fmt.Errorf("MASQUE server did not acknowledge Capsule Protocol")
		}
	}
	finishSetup()
	if err := setup.Err(); err != nil {
		return nil, err
	}
	_ = str.SetDeadline(time.Time{})
	keep = true
	return stream, nil
}

func (c *Client) DialStream(ctx context.Context, target string) (transport.StreamConn, error) {
	return c.open(ctx, target, false)
}

func (c *Client) Close() error {
	c.cancel()
	c.mu.Lock()
	c.closed = true
	packets := make([]*packetConn, 0, len(c.packets))
	for p := range c.packets {
		packets = append(packets, p)
	}
	generations := make([]*connectionGeneration, 0, len(c.generations))
	for _, g := range c.generations {
		generations = append(generations, g)
	}
	c.conn = nil
	c.mu.Unlock()
	for _, g := range generations {
		g.close()
	}
	for _, p := range packets {
		_ = p.Close()
	}
	<-c.senderDone
	return nil
}

type streamConn struct {
	*http3.RequestStream
	local, remote net.Addr
	once          sync.Once
	closed        atomic.Bool
	readMu        chan struct{}
	done          chan struct{}
	deadlineMu    sync.Mutex
	writeMu       sync.Mutex
	closeErr      error
	release       func()
}

func (s *streamConn) LocalAddr() net.Addr  { return s.local }
func (s *streamConn) RemoteAddr() net.Addr { return s.remote }
func (s *streamConn) Read(b []byte) (int, error) {
	if s.closed.Load() {
		return 0, net.ErrClosed
	}
	select {
	case s.readMu <- struct{}{}:
	case <-s.done:
		return 0, net.ErrClosed
	}
	defer func() { <-s.readMu }()
	if s.closed.Load() {
		return 0, net.ErrClosed
	}
	n, err := s.RequestStream.Read(b)
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
	return s.RequestStream.Write(b)
}
func (s *streamConn) Close() error {
	s.once.Do(func() {
		s.deadlineMu.Lock()
		s.closed.Store(true)
		close(s.done)
		// Interrupt public reads without sending STOP_SENDING before the peer
		// has had a chance to consume our payload and FIN.
		_ = s.RequestStream.SetReadDeadline(time.Now())
		s.deadlineMu.Unlock()
		if s.writeMu.TryLock() {
			// The patched HTTP/3 tracker retains normal sends until QUIC ACKs
			// data and FIN, even if reads already reached EOF before GOAWAY.
			s.closeErr = s.RequestStream.Close()
			s.writeMu.Unlock()
			deadline := time.Now().Add(closeSendTimeout)
			go func() {
				defer s.release()
				s.readMu <- struct{}{}
				defer func() { <-s.readMu }()
				_ = s.RequestStream.SetReadDeadline(deadline)
				_, _ = io.Copy(io.Discard, s.RequestStream)
				s.CancelRead(0)
				// Both response drain and ACK wait share one absolute deadline.
				timer := time.NewTimer(time.Until(deadline))
				defer timer.Stop()
				select {
				case <-s.SendCompletionContext().Done():
				case <-timer.C:
					s.CancelWrite(0)
				}
			}()
		} else {
			// Close must interrupt an in-progress flow-controlled Write.
			s.CancelRead(0)
			s.CancelWrite(0)
			s.release()
		}
	})
	return s.closeErr
}

func (s *streamConn) abort() {
	s.once.Do(func() { s.closed.Store(true); close(s.done); s.CancelRead(0); s.CancelWrite(0); s.release() })
}
func (s *streamConn) CloseRead() error {
	s.deadlineMu.Lock()
	defer s.deadlineMu.Unlock()
	if s.closed.Load() {
		return net.ErrClosed
	}
	s.CancelRead(0)
	return nil
}
func (s *streamConn) CloseWrite() error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.closed.Load() {
		return net.ErrClosed
	}
	return s.RequestStream.Close()
}

func (s *streamConn) SetDeadline(t time.Time) error {
	s.deadlineMu.Lock()
	defer s.deadlineMu.Unlock()
	if s.closed.Load() {
		return net.ErrClosed
	}
	return s.RequestStream.SetDeadline(t)
}
func (s *streamConn) SetReadDeadline(t time.Time) error {
	s.deadlineMu.Lock()
	defer s.deadlineMu.Unlock()
	if s.closed.Load() {
		return net.ErrClosed
	}
	return s.RequestStream.SetReadDeadline(t)
}
func (s *streamConn) SetWriteDeadline(t time.Time) error {
	s.deadlineMu.Lock()
	defer s.deadlineMu.Unlock()
	if s.closed.Load() {
		return net.ErrClosed
	}
	return s.RequestStream.SetWriteDeadline(t)
}

type statusError int

func (e statusError) Error() string {
	return fmt.Sprintf("MASQUE CONNECT rejected (status %d)", int(e))
}
func (e statusError) HTTPStatusCode() int { return int(e) }
