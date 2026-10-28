// Package naive implements the CONNECT and padding protocol documented at
// https://github.com/klzgrad/naiveproxy#padding-protocol-an-informal-specification.
package naive

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"bimeron/internal/accesskey"
	"bimeron/internal/streamtransport"
	"github.com/quic-go/quic-go/http3"
	utls "github.com/refraction-networking/utls"
	"golang.getoutline.org/sdk/transport"
	"golang.org/x/net/http2"
)

const firstPaddings = 8

type Client struct {
	profile     accesskey.Profile
	rootCAs     *x509.CertPool
	transport   http.RoundTripper
	h3          *http3.Transport
	sockets     map[net.PacketConn]struct{}
	mu          sync.Mutex
	streams     map[*stream]struct{}
	connections map[*trackedConn]struct{}
	closed      bool
	ctx         context.Context
	cancel      context.CancelFunc
}

var _ transport.StreamDialer = (*Client)(nil)
var _ transport.StreamConn = (*stream)(nil)

func New(profile accesskey.Profile, dialer net.Dialer) (*Client, error) {
	if err := profile.ValidateShadowTLS(); err != nil {
		return nil, err
	}
	if profile.Type != "naive" {
		return nil, fmt.Errorf("expected NaiveProxy profile")
	}
	if err := profile.Naive.Validate(profile.TCP.Host, profile.TCP.Port); err != nil {
		return nil, err
	}
	c := &Client{profile: profile, streams: make(map[*stream]struct{}), connections: make(map[*trackedConn]struct{})}
	c.ctx, c.cancel = context.WithCancel(context.Background())
	if profile.Naive.QUIC {
		c.sockets = make(map[net.PacketConn]struct{})
		c.h3 = &http3.Transport{Dial: c.quicDialer(dialer), DisableCompression: true}
		c.transport = c.h3
		return c, nil
	}
	c.transport = &http2.Transport{IdleConnTimeout: 60 * time.Second, DialTLSContext: func(ctx context.Context, _, _ string, _ *tls.Config) (net.Conn, error) {
		ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		stop := context.AfterFunc(c.ctx, cancel)
		defer stop()
		endpoint := net.JoinHostPort(profile.TCP.Host, strconv.Itoa(profile.TCP.Port))
		raw, err := streamtransport.Dial(ctx, dialer, endpoint, profile.ShadowTLS, c.rootCAs)
		if err != nil {
			return nil, err
		}
		tracked := &trackedConn{Conn: raw, client: c}
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			_ = raw.Close()
			return nil, net.ErrClosed
		}
		c.connections[tracked] = struct{}{}
		c.mu.Unlock()
		raw = tracked
		conn, err := streamtransport.TLS(ctx, raw, profile.Naive.ServerName, []string{"h2"}, "chrome", c.rootCAs)
		if err != nil {
			_ = raw.Close()
			return nil, fmt.Errorf("NaiveProxy TLS failed")
		}
		if conn.(*utls.UConn).ConnectionState().NegotiatedProtocol != "h2" {
			_ = conn.Close()
			return nil, fmt.Errorf("NaiveProxy server did not negotiate HTTP/2")
		}
		return conn, nil
	}}
	return c, nil
}

func (c *Client) DialStream(ctx context.Context, target string) (transport.StreamConn, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil || host == "" || port == "" {
		return nil, fmt.Errorf("invalid NaiveProxy destination")
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return nil, fmt.Errorf("invalid NaiveProxy destination")
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, net.ErrClosed
	}
	c.mu.Unlock()
	// DialStream's context governs setup only. Callers cancel it immediately
	// after connecting; the established stream belongs to the client lifetime.
	requestCtx, cancel := context.WithCancel(c.ctx)
	stop := context.AfterFunc(ctx, cancel)
	setupTimer := time.AfterFunc(15*time.Second, cancel)
	reader, writer := io.Pipe()
	// Pool connections by proxy, while CONNECT's authority is the target.
	endpoint := net.JoinHostPort(c.profile.TCP.Host, strconv.Itoa(c.profile.TCP.Port))
	req := &http.Request{Method: http.MethodConnect, URL: &url.URL{Scheme: "https", Host: endpoint}, Host: target, Header: make(http.Header), Body: reader, ContentLength: -1}
	req = req.WithContext(requestCtx)
	req.SetBasicAuth(c.profile.Naive.User, c.profile.Naive.Password)
	req.Header.Set("Proxy-Authorization", req.Header.Get("Authorization"))
	req.Header.Del("Authorization")
	req.Header.Set("Padding", headerPadding())
	resp, err := c.transport.RoundTrip(req)
	setupTimer.Stop()
	stop()
	if err != nil {
		cancel()
		_ = writer.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("NaiveProxy CONNECT failed")
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		cancel()
		_ = writer.Close()
		return nil, fmt.Errorf("NaiveProxy CONNECT rejected with HTTP %d", resp.StatusCode)
	}
	_, padded := resp.Header["Padding"]
	s := &stream{client: c, target: target, reader: resp.Body, writer: writer, cancel: cancel, padded: padded}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		_ = s.Close()
		return nil, net.ErrClosed
	}
	c.streams[s] = struct{}{}
	c.mu.Unlock()
	return s, nil
}

func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	streams := make([]*stream, 0, len(c.streams))
	for s := range c.streams {
		streams = append(streams, s)
	}
	connections := make([]*trackedConn, 0, len(c.connections))
	for conn := range c.connections {
		connections = append(connections, conn)
	}
	sockets := make([]net.PacketConn, 0, len(c.sockets))
	for socket := range c.sockets {
		sockets = append(sockets, socket)
	}
	c.mu.Unlock()
	c.cancel()
	for _, socket := range sockets {
		_ = socket.Close()
	}
	for _, conn := range connections {
		_ = conn.Close()
	}
	for _, s := range streams {
		_ = s.Close()
	}
	if c.h3 != nil {
		_ = c.h3.Close()
	} else {
		c.transport.(*http2.Transport).CloseIdleConnections()
	}
	return nil
}

type trackedConn struct {
	net.Conn
	client *Client
	once   sync.Once
}

func (c *trackedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { c.client.mu.Lock(); delete(c.client.connections, c); c.client.mu.Unlock() })
	return err
}

type stream struct {
	client     *Client
	target     string
	reader     io.ReadCloser
	writer     *io.PipeWriter
	cancel     context.CancelFunc
	padded     bool
	readMu     sync.Mutex
	writeMu    sync.Mutex
	readBuf    []byte
	reads      int
	writes     int
	closeOnce  sync.Once
	deadlineMu sync.Mutex
	deadline   *time.Timer
}

func (s *stream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	s.readMu.Lock()
	defer s.readMu.Unlock()
	if !s.padded || s.reads >= firstPaddings {
		if len(s.readBuf) == 0 {
			return s.reader.Read(p)
		}
	}
	for len(s.readBuf) == 0 && s.reads < firstPaddings {
		var header [3]byte
		if _, err := io.ReadFull(s.reader, header[:]); err != nil {
			return 0, err
		}
		length := int(binary.BigEndian.Uint16(header[:2]))
		padding := int(header[2])
		payload := make([]byte, length)
		if _, err := io.ReadFull(s.reader, payload); err != nil {
			return 0, err
		}
		if _, err := io.CopyN(io.Discard, s.reader, int64(padding)); err != nil {
			return 0, err
		}
		s.readBuf = payload
		s.reads++
	}
	if len(s.readBuf) == 0 {
		return s.reader.Read(p)
	}
	n := copy(p, s.readBuf)
	s.readBuf = s.readBuf[n:]
	return n, nil
}

func (s *stream) Write(p []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	written := 0
	for len(p) > 0 {
		if !s.padded || s.writes >= firstPaddings {
			n, err := s.writer.Write(p)
			return written + n, err
		}
		chunk := p[:min(len(p), 65535)]
		var random [1]byte
		if _, err := rand.Read(random[:]); err != nil {
			return written, err
		}
		frame := make([]byte, 3+len(chunk)+int(random[0]))
		binary.BigEndian.PutUint16(frame[:2], uint16(len(chunk)))
		frame[2] = random[0]
		copy(frame[3:], chunk)
		if _, err := s.writer.Write(frame); err != nil {
			return written, err
		}
		written += len(chunk)
		p = p[len(chunk):]
		s.writes++
	}
	return written, nil
}

func (s *stream) CloseWrite() error { return s.writer.Close() }
func (s *stream) CloseRead() error  { return s.reader.Close() }
func (s *stream) Close() error {
	s.closeOnce.Do(func() {
		s.deadlineMu.Lock()
		if s.deadline != nil {
			s.deadline.Stop()
		}
		s.deadlineMu.Unlock()
		s.cancel()
		_ = s.writer.Close()
		_ = s.reader.Close()
		s.client.mu.Lock()
		delete(s.client.streams, s)
		s.client.mu.Unlock()
	})
	return nil
}
func (s *stream) LocalAddr() net.Addr  { return proxyAddr("local") }
func (s *stream) RemoteAddr() net.Addr { return proxyAddr(s.target) }
func (s *stream) SetDeadline(t time.Time) error {
	// ponytail: an expired deadline terminates the stream, as in the gRPC adapter;
	// reusable per-direction deadlines would require buffered asynchronous I/O.
	s.deadlineMu.Lock()
	defer s.deadlineMu.Unlock()
	if s.deadline != nil {
		s.deadline.Stop()
		s.deadline = nil
	}
	if !t.IsZero() {
		// Canceling the request context alone can leave HTTP/2 blocked reading
		// the request pipe after RoundTrip returns. Close both halves as well.
		s.deadline = time.AfterFunc(max(0, time.Until(t)), func() { _ = s.Close() })
	}
	return nil
}
func (s *stream) SetReadDeadline(t time.Time) error  { return s.SetDeadline(t) }
func (s *stream) SetWriteDeadline(t time.Time) error { return s.SetDeadline(t) }

type proxyAddr string

func (a proxyAddr) Network() string { return "tcp" }
func (a proxyAddr) String() string  { return string(a) }

func headerPadding() string {
	var random [33]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "0000000000000000"
	}
	for random[0] == 255 {
		_, _ = rand.Read(random[:1])
	}
	length := 16 + int(random[0])%17
	const alphabet = "!#$()+<>?@[]^`{}"
	buf := make([]byte, length)
	for i := range buf {
		buf[i] = alphabet[int(random[i+1])%len(alphabet)]
	}
	return string(buf)
}
