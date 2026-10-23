package vless

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

// xhttpStream implements the default Xray path placement and padding for
// stream-one and packet-up. Every physical HTTP/2 connection uses c.dialer.
func (c *Client) xhttpStream(ctx context.Context) (net.Conn, error) {
	// The dialing context may end immediately after DialStream returns.
	streamCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	transport, transportErr := c.xhttpClientTransport()
	if transportErr != nil {
		cancel()
		return nil, transportErr
	}
	host := c.settings.XHTTPHost
	if host == "" {
		host = c.settings.ServerName
	}
	if host == "" {
		host = c.endpoint.Host
	}
	path := c.settings.XHTTPPath
	if path == "" {
		path = "/"
	}
	u, err := url.Parse("https://" + host + path)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("invalid XHTTP URL")
	}
	if !strings.HasSuffix(u.Path, "/") {
		u.Path += "/"
	}
	x := &xhttpConn{ctx: streamCtx, cancel: cancel, client: &http.Client{Transport: transport}, base: *u,
		remote: grpcAddr(net.JoinHostPort(c.endpoint.Host, strconv.Itoa(c.endpoint.Port))), ready: make(chan struct{}), mode: c.settings.XHTTPMode}
	if x.mode == "stream-one" {
		x.reader, x.writer = io.Pipe()
		go x.download(x.base, x.reader)
	} else {
		var id [16]byte
		if _, err := rand.Read(id[:]); err != nil {
			cancel()
			return nil, fmt.Errorf("XHTTP session creation failed")
		}
		x.session = hex.EncodeToString(id[:])
		x.upload = make(chan []byte, 8)
		go x.download(x.sessionURL(""), nil)
		go x.uploadPackets()
	}
	return x, nil
}

func (c *Client) xhttpClientTransport() (*http2.Transport, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, net.ErrClosed
	}
	if c.xhttpTransport != nil {
		return c.xhttpTransport, nil
	}
	c.xhttpTransport = &http2.Transport{DialTLSContext: func(dialCtx context.Context, _, _ string, _ *tls.Config) (net.Conn, error) {
		address := net.JoinHostPort(c.endpoint.Host, strconv.Itoa(c.endpoint.Port))
		raw, err := c.dialer.DialContext(dialCtx, "tcp", address)
		if err != nil {
			return nil, err
		}
		var secure net.Conn
		if c.settings.Security == "reality" {
			secure, err = realityHandshake(dialCtx, raw, c.settings, c.publicKey, c.shortID)
		} else {
			secure, err = c.tlsHandshake(dialCtx, raw)
		}
		if err != nil {
			_ = raw.Close()
			return nil, err
		}
		return secure, nil
	}}
	return c.xhttpTransport, nil
}

type xhttpConn struct {
	ctx           context.Context
	cancel        context.CancelFunc
	client        *http.Client
	base          url.URL
	remote        net.Addr
	mode, session string
	reader        *io.PipeReader
	writer        *io.PipeWriter
	upload        chan []byte
	ready         chan struct{}
	mu            sync.Mutex
	body          io.ReadCloser
	readErr       error
	uploadErr     error
	writeClosed   bool
	deadline      *time.Timer
	once          sync.Once
}

func (x *xhttpConn) sessionURL(seq string) url.URL {
	u := x.base
	u.Path += x.session
	if seq != "" {
		u.Path += "/" + seq
	}
	return u
}
func (x *xhttpConn) request(method string, u url.URL, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(x.ctx, method, u.String(), body)
	if err != nil {
		return nil, err
	}
	// Xray's default XHTTP server validates a 100..1000 byte x_padding value.
	referer := u
	q := referer.Query()
	q.Set("x_padding", strings.Repeat("X", 100))
	referer.RawQuery = q.Encode()
	req.Header.Set("Referer", referer.String())
	if body != nil && x.mode == "stream-one" {
		req.Header.Set("Content-Type", "application/grpc")
	}
	return req, nil
}
func (x *xhttpConn) download(u url.URL, body io.Reader) {
	method := http.MethodGet
	if body != nil {
		method = http.MethodPost
	}
	req, err := x.request(method, u, body)
	if err == nil {
		var resp *http.Response
		resp, err = x.client.Do(req)
		if err == nil {
			if resp.StatusCode == http.StatusOK {
				x.mu.Lock()
				x.body = resp.Body
				x.mu.Unlock()
			} else {
				_ = resp.Body.Close()
				err = fmt.Errorf("XHTTP response status %d", resp.StatusCode)
			}
		}
	}
	x.mu.Lock()
	x.readErr = err
	x.mu.Unlock()
	close(x.ready)
}
func (x *xhttpConn) uploadPackets() {
	var seq uint64
	for {
		select {
		case <-x.ctx.Done():
			return
		case first, ok := <-x.upload:
			if !ok {
				return
			}
			buf := append([]byte(nil), first...)
			timer := time.NewTimer(10 * time.Millisecond)
		collect:
			for len(buf) < 64*1024 {
				select {
				case more, ok := <-x.upload:
					if !ok {
						break collect
					}
					buf = append(buf, more...)
				case <-timer.C:
					break collect
				case <-x.ctx.Done():
					timer.Stop()
					return
				}
			}
			timer.Stop()
			u := x.sessionURL(strconv.FormatUint(seq, 10))
			seq++
			req, err := x.request(http.MethodPost, u, bytes.NewReader(buf))
			if err == nil {
				var resp *http.Response
				resp, err = x.client.Do(req)
				if err == nil {
					_, _ = io.Copy(io.Discard, resp.Body)
					_ = resp.Body.Close()
					if resp.StatusCode != http.StatusOK {
						err = fmt.Errorf("XHTTP upload status %d", resp.StatusCode)
					}
				}
			}
			if err != nil {
				x.cancel()
				x.mu.Lock()
				x.uploadErr = err
				x.mu.Unlock()
				return
			}
		}
	}
}
func (x *xhttpConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	select {
	case <-x.ready:
	case <-x.ctx.Done():
		return 0, x.ctx.Err()
	}
	x.mu.Lock()
	body, err := x.body, x.readErr
	x.mu.Unlock()
	if err != nil {
		return 0, err
	}
	if body == nil {
		return 0, io.ErrClosedPipe
	}
	return body.Read(p)
}
func (x *xhttpConn) Write(p []byte) (int, error) {
	if x.mode == "stream-one" {
		return x.writer.Write(p)
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.writeClosed {
		return 0, io.ErrClosedPipe
	}
	if x.uploadErr != nil {
		return 0, x.uploadErr
	}
	written := 0
	for len(p) > 0 {
		n := min(len(p), 64*1024)
		chunk := append([]byte(nil), p[:n]...)
		select {
		case x.upload <- chunk:
			written += n
			p = p[n:]
		case <-x.ctx.Done():
			return written, x.ctx.Err()
		}
	}
	return written, nil
}
func (x *xhttpConn) CloseWrite() error {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.writeClosed {
		return nil
	}
	x.writeClosed = true
	if x.mode == "stream-one" {
		return x.writer.Close()
	}
	close(x.upload)
	return nil
}
func (x *xhttpConn) Close() error {
	x.once.Do(func() {
		x.cancel()
		x.mu.Lock()
		if x.deadline != nil {
			x.deadline.Stop()
		}
		if x.body != nil {
			_ = x.body.Close()
		}
		x.mu.Unlock()
		if x.reader != nil {
			_ = x.reader.Close()
		}
		if x.writer != nil {
			_ = x.writer.Close()
		}
	})
	return nil
}
func (x *xhttpConn) LocalAddr() net.Addr  { return grpcAddr("local") }
func (x *xhttpConn) RemoteAddr() net.Addr { return x.remote }
func (x *xhttpConn) SetDeadline(t time.Time) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.deadline != nil {
		x.deadline.Stop()
		x.deadline = nil
	}
	if !t.IsZero() {
		x.deadline = time.AfterFunc(max(0, time.Until(t)), x.cancel)
	}
	return nil
}
func (x *xhttpConn) SetReadDeadline(t time.Time) error  { return x.SetDeadline(t) }
func (x *xhttpConn) SetWriteDeadline(t time.Time) error { return x.SetDeadline(t) }

var _ net.Conn = (*xhttpConn)(nil)
