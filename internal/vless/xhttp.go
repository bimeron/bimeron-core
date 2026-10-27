package vless

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
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
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
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
	u, err := url.Parse("https://" + xhttpURLHost(host) + path)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("invalid XHTTP URL")
	}
	if !strings.HasSuffix(u.Path, "/") {
		u.Path += "/"
	}
	mode := c.settings.XHTTPMode
	if mode == "auto" {
		if c.settings.Security == "reality" {
			mode = "stream-one"
		} else {
			mode = "packet-up"
		}
	}
	x := &xhttpConn{ctx: streamCtx, cancel: cancel, client: &http.Client{Transport: transport}, base: *u,
		remote: grpcAddr(net.JoinHostPort(c.endpoint.Host, strconv.Itoa(c.endpoint.Port))), ready: make(chan struct{}), mode: mode, options: c.settings.XHTTPOptions}
	if x.options != nil && x.options.DownloadSettings != nil {
		download := x.options.DownloadSettings
		client, err := c.xhttpDownloadClient(download)
		if err != nil {
			cancel()
			return nil, err
		}
		separate, err := client.xhttpClientTransport()
		if err != nil {
			cancel()
			return nil, err
		}
		x.downloadClient = &http.Client{Transport: separate}
		host := download.Host
		if host == "" {
			host = download.ServerName
		}
		if host == "" {
			host = download.Address
		}
		path := download.Path
		if path == "" {
			path = c.settings.XHTTPPath
		}
		if path == "" {
			path = "/"
		}
		downloadURL, err := url.Parse("https://" + xhttpURLHost(host) + path)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("invalid XHTTP download URL")
		}
		if !strings.HasSuffix(downloadURL.Path, "/") {
			downloadURL.Path += "/"
		}
		x.downloadBase = *downloadURL
	}
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
		if mode == "stream-up" {
			x.reader, x.writer = io.Pipe()
		} else {
			buffered := 8
			if x.options != nil && x.options.ScMaxBufferedPosts > 0 {
				buffered = x.options.ScMaxBufferedPosts
			}
			x.upload = make(chan []byte, buffered)
		}
		go x.download(x.downloadURL(), nil)
		if mode == "stream-up" {
			go x.uploadStream()
		} else {
			go x.uploadPackets()
		}
	}
	return x, nil
}

func xhttpURLHost(host string) string {
	if strings.Contains(host, ":") && net.ParseIP(host) != nil {
		return "[" + host + "]"
	}
	return host
}

func (c *Client) xhttpDownloadClient(d *accesskey.XHTTPDownloadSettings) (*Client, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, net.ErrClosed
	}
	if c.xhttpDownload != nil {
		return c.xhttpDownload, nil
	}
	settings := c.settings
	settings.Security, settings.ServerName, settings.ALPN, settings.Fingerprint = d.Security, d.ServerName, d.ALPN, d.Fingerprint
	settings.PublicKey, settings.ShortID, settings.XHTTPOptions = d.PublicKey, d.ShortID, nil
	address := d.ResolvedAddress
	if address == "" {
		address = d.Address
	}
	key, _ := base64.RawURLEncoding.DecodeString(d.PublicKey)
	sid, _ := hex.DecodeString(d.ShortID)
	client := &Client{endpoint: accesskey.Endpoint{Host: address, Port: d.Port}, settings: settings, publicKey: key, shortID: sid, dialer: c.dialer, connections: make(map[*streamConn]struct{}), packets: make(map[*packetConn]struct{})}
	c.xhttpDownload = client
	return client, nil
}

func (c *Client) xhttpClientTransport() (http.RoundTripper, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, net.ErrClosed
	}
	if c.settings.ALPN == "h3" {
		if c.xhttpH3Transport != nil {
			return c.xhttpH3Transport, nil
		}
		family, bind := "udp4", "0.0.0.0:0"
		if strings.Contains(c.endpoint.Host, ":") {
			family, bind = "udp6", "[::]:0"
		}
		lc := net.ListenConfig{Control: c.dialer.Control}
		packet, err := lc.ListenPacket(context.Background(), family, bind)
		if err != nil {
			return nil, fmt.Errorf("XHTTP HTTP/3 socket unavailable: %w", err)
		}
		address := net.JoinHostPort(c.endpoint.Host, strconv.Itoa(c.endpoint.Port))
		if net.ParseIP(c.endpoint.Host) == nil {
			_ = packet.Close()
			return nil, fmt.Errorf("XHTTP HTTP/3 requires a resolved server address")
		}
		remote, err := net.ResolveUDPAddr(family, address)
		if err != nil {
			_ = packet.Close()
			return nil, fmt.Errorf("XHTTP HTTP/3 endpoint unavailable")
		}
		qt := &quic.Transport{Conn: packet}
		name := c.settings.ServerName
		if name == "" {
			name = c.endpoint.Host
		}
		h3 := &http3.Transport{TLSClientConfig: &tls.Config{ServerName: name, NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13, RootCAs: c.rootCAs}, Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			return qt.DialEarly(ctx, remote, tlsCfg, cfg)
		}}
		c.xhttpPacket, c.xhttpQUIC, c.xhttpH3Transport = packet, qt, h3
		return h3, nil
	}
	if c.xhttpTransport != nil {
		return c.xhttpTransport, nil
	}
	if c.xhttpPool != nil {
		return c.xhttpPool, nil
	}
	if c.settings.XHTTPOptions != nil && c.settings.XHTTPOptions.Xmux != nil {
		c.xhttpPool = newXHTTPMuxPool(c.xhttpDial, c.settings.XHTTPOptions.Xmux)
		return c.xhttpPool, nil
	}
	c.xhttpTransport = &http2.Transport{DialTLSContext: func(ctx context.Context, _, _ string, _ *tls.Config) (net.Conn, error) { return c.xhttpDial(ctx) }}
	return c.xhttpTransport, nil
}

func (c *Client) xhttpDial(ctx context.Context) (net.Conn, error) {
	address := net.JoinHostPort(c.endpoint.Host, strconv.Itoa(c.endpoint.Port))
	raw, err := c.dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	if options := c.settings.XHTTPOptions; options != nil && options.Xmux != nil && options.Xmux.HKeepAlivePeriod > 0 {
		if tcp, ok := raw.(*net.TCPConn); ok {
			_ = tcp.SetKeepAlive(true)
			_ = tcp.SetKeepAlivePeriod(time.Duration(options.Xmux.HKeepAlivePeriod) * time.Second)
		}
	}
	var secure net.Conn
	if c.settings.Security == "reality" {
		secure, err = realityHandshake(ctx, raw, c.settings, c.publicKey, c.shortID)
	} else {
		secure, err = c.tlsHandshake(ctx, raw)
	}
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	return secure, nil
}

type xhttpConn struct {
	ctx             context.Context
	cancel          context.CancelFunc
	client          *http.Client
	downloadClient  *http.Client
	base            url.URL
	downloadBase    url.URL
	remote          net.Addr
	mode, session   string
	options         *accesskey.XHTTPOptions
	reader          *io.PipeReader
	writer          *io.PipeWriter
	upload          chan []byte
	ready           chan struct{}
	mu              sync.Mutex
	body            io.ReadCloser
	readErr         error
	uploadErr       error
	uploadMu        sync.Mutex
	writeClosed     bool
	deadline        *time.Timer
	deadlineExpired atomic.Bool
	once            sync.Once
}

func (x *xhttpConn) sessionURL(seq string) url.URL {
	u := x.base
	if x.session != "" && (x.options == nil || x.options.SessionPlacement == "" || x.options.SessionPlacement == "path") {
		u.Path += x.session
	}
	if seq != "" && (x.options == nil || x.options.SeqPlacement == "" || x.options.SeqPlacement == "path") {
		u.Path += "/" + seq
	}
	return u
}
func (x *xhttpConn) downloadURL() url.URL {
	if x.downloadClient == nil {
		return x.sessionURL("")
	}
	u := x.downloadBase
	if x.session != "" && (x.options.SessionPlacement == "" || x.options.SessionPlacement == "path") {
		u.Path += x.session
	}
	return u
}
func (x *xhttpConn) request(method string, u url.URL, body io.Reader, seq string) (*http.Request, error) {
	return xhttpRequest(x.ctx, method, u, body, x.session, seq, x.mode, x.options)
}
func (x *xhttpConn) uploadStream() {
	u := x.sessionURL("")
	req, err := x.request(x.uplinkMethod(), u, x.reader, "")
	if err == nil {
		var resp *http.Response
		resp, err = x.client.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				err = xhttpStatusError{resp.StatusCode}
			}
		}
	}
	if err != nil {
		x.failUpload(err)
	}
}
func (x *xhttpConn) download(u url.URL, body io.Reader) {
	method := http.MethodGet
	if body != nil {
		method = http.MethodPost
	}
	req, err := x.request(method, u, body, "")
	if err == nil {
		var resp *http.Response
		client := x.client
		if x.downloadClient != nil {
			client = x.downloadClient
		}
		resp, err = client.Do(req)
		if err == nil {
			if resp.StatusCode == http.StatusOK {
				x.mu.Lock()
				x.body = resp.Body
				x.mu.Unlock()
			} else {
				_ = resp.Body.Close()
				err = xhttpStatusError{resp.StatusCode}
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
	var pending []byte
	for {
		first := pending
		pending = nil
		if first == nil {
			select {
			case <-x.ctx.Done():
				return
			case chunk, ok := <-x.upload:
				if !ok {
					return
				}
				first = chunk
			}
		}
		{
			buf := append([]byte(nil), first...)
			maxBytes, interval := 64*1024, 10*time.Millisecond
			if x.options != nil {
				if x.options.ScMaxEachPostBytes.To > 0 {
					maxBytes = xhttpRangeValue(x.options.ScMaxEachPostBytes, maxBytes)
				}
				if x.options.ScMinPostsIntervalMs.To > 0 {
					interval = time.Duration(xhttpRangeValue(x.options.ScMinPostsIntervalMs, 10)) * time.Millisecond
				}
			}
			timer := time.NewTimer(interval)
		collect:
			for len(buf) < maxBytes {
				select {
				case more, ok := <-x.upload:
					if !ok {
						break collect
					}
					capacity := maxBytes - len(buf)
					if len(more) > capacity {
						buf = append(buf, more[:capacity]...)
						pending = append([]byte(nil), more[capacity:]...)
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
			req, err := x.request(x.uplinkMethod(), u, bytes.NewReader(buf), strconv.FormatUint(seq-1, 10))
			if err == nil {
				var resp *http.Response
				resp, err = x.client.Do(req)
				if err == nil {
					_, _ = io.Copy(io.Discard, resp.Body)
					_ = resp.Body.Close()
					if resp.StatusCode != http.StatusOK {
						err = xhttpStatusError{resp.StatusCode}
					}
				}
			}
			if err != nil {
				x.failUpload(err)
				return
			}
		}
	}
}
func (x *xhttpConn) uplinkMethod() string {
	if x.options != nil && x.options.UplinkHTTPMethod != "" {
		return x.options.UplinkHTTPMethod
	}
	return http.MethodPost
}

// Expose only the numeric HTTP status to diagnostics, never request metadata.
type xhttpStatusError struct{ status int }

func (e xhttpStatusError) Error() string       { return fmt.Sprintf("XHTTP status %d", e.status) }
func (e xhttpStatusError) HTTPStatusCode() int { return e.status }

func (x *xhttpConn) failUpload(err error) {
	// Write can hold mu while waiting for queue space. Publishing the error
	// must not wait for that lock before cancellation releases the writer.
	x.uploadMu.Lock()
	x.uploadErr = err
	x.uploadMu.Unlock()
	x.cancel()
}

func (x *xhttpConn) streamError(err error) error {
	if err != nil && x.deadlineExpired.Load() {
		return os.ErrDeadlineExceeded
	}
	x.uploadMu.Lock()
	uploadErr := x.uploadErr
	x.uploadMu.Unlock()
	if uploadErr != nil {
		return uploadErr
	}
	return err
}

func (x *xhttpConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	select {
	case <-x.ready:
	case <-x.ctx.Done():
		return 0, x.streamError(x.ctx.Err())
	}
	x.mu.Lock()
	body, err := x.body, x.readErr
	x.mu.Unlock()
	if err != nil {
		return 0, x.streamError(err)
	}
	if body == nil {
		return 0, io.ErrClosedPipe
	}
	n, err := body.Read(p)
	if err != nil {
		return n, x.streamError(err)
	}
	return n, nil
}
func (x *xhttpConn) Write(p []byte) (int, error) {
	if x.mode == "stream-one" || x.mode == "stream-up" {
		return x.writer.Write(p)
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.writeClosed {
		return 0, io.ErrClosedPipe
	}
	if err := x.streamError(nil); err != nil {
		return 0, err
	}
	written := 0
	chunkLimit := 64 * 1024
	if x.options != nil && x.options.ScMaxEachPostBytes.To > 0 {
		chunkLimit = min(chunkLimit, x.options.ScMaxEachPostBytes.From)
	}
	for len(p) > 0 {
		n := min(len(p), chunkLimit)
		chunk := append([]byte(nil), p[:n]...)
		select {
		case x.upload <- chunk:
			written += n
			p = p[n:]
		case <-x.ctx.Done():
			return written, x.streamError(x.ctx.Err())
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
	if x.mode == "stream-one" || x.mode == "stream-up" {
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
	x.deadlineExpired.Store(false)
	if !t.IsZero() {
		x.deadline = time.AfterFunc(max(0, time.Until(t)), func() { x.deadlineExpired.Store(true); x.cancel() })
	}
	return nil
}
func (x *xhttpConn) SetReadDeadline(t time.Time) error  { return x.SetDeadline(t) }
func (x *xhttpConn) SetWriteDeadline(t time.Time) error { return x.SetDeadline(t) }

var _ net.Conn = (*xhttpConn)(nil)
