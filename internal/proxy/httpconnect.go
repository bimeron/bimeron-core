package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"bimeron/internal/accesskey"
	"bimeron/internal/streamtransport"
	"golang.getoutline.org/sdk/transport"
)

// HTTPConnect dials TCP destinations through a remote HTTP/1.1 proxy.
type HTTPConnect struct {
	Endpoint   accesskey.Endpoint
	Username   string
	Dialer     net.Dialer
	ServerName string         // Nonempty enables TLS; independent of the resolved endpoint.
	rootCAs    *x509.CertPool // Test-only roots; nil uses system trust.
}

var _ transport.StreamDialer = (*HTTPConnect)(nil)

func (p *HTTPConnect) DialStream(ctx context.Context, target string) (transport.StreamConn, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil || host == "" || port == "" || strings.ContainsAny(target, "\r\n\t ") {
		return nil, fmt.Errorf("invalid HTTP CONNECT destination")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return nil, fmt.Errorf("invalid HTTP CONNECT destination port")
	}
	conn, err := p.Dialer.DialContext(ctx, "tcp", net.JoinHostPort(p.Endpoint.Host, strconv.Itoa(p.Endpoint.Port)))
	if err != nil {
		return nil, err
	}
	raw := conn.(*net.TCPConn)
	c := conn
	ok := false
	defer func() {
		if !ok {
			_ = raw.Close()
		}
	}()
	stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer stop()
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	if p.ServerName != "" {
		c, err = streamtransport.TLS(ctx, raw, p.ServerName, []string{"http/1.1"}, "", p.rootCAs)
		if err != nil {
			return nil, fmt.Errorf("HTTPS proxy TLS failed: %w", err)
		}
	}
	request := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n"
	if p.Username != "" {
		credentials := base64.StdEncoding.EncodeToString([]byte(p.Username + ":" + p.Endpoint.Secret))
		request += "Proxy-Authorization: Basic " + credentials + "\r\n"
	}
	if _, err = io.WriteString(c, request+"\r\n"); err != nil {
		return nil, err
	}
	reader := bufio.NewReaderSize(c, 4096)
	var header bytes.Buffer
	for header.Len() < 16*1024 {
		line, readErr := reader.ReadSlice('\n')
		if readErr != nil || header.Len()+len(line) > 16*1024 {
			return nil, fmt.Errorf("invalid or oversized HTTP CONNECT response")
		}
		header.Write(line)
		if bytes.Equal(line, []byte("\r\n")) {
			break
		}
	}
	if !bytes.HasSuffix(header.Bytes(), []byte("\r\n\r\n")) {
		return nil, fmt.Errorf("invalid or oversized HTTP CONNECT response")
	}
	response, err := http.ReadResponse(bufio.NewReader(&header), &http.Request{Method: http.MethodConnect})
	if err != nil {
		return nil, fmt.Errorf("invalid HTTP CONNECT response")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP CONNECT rejected (status %d)", response.StatusCode)
	}
	_ = c.SetDeadline(time.Time{})
	ok = true
	if p.ServerName == "" && reader.Buffered() == 0 {
		return raw, nil
	}
	return &bufferedConn{Conn: c, raw: raw, reader: reader}, nil
}

type bufferedConn struct {
	net.Conn
	raw    *net.TCPConn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) { return c.reader.Read(b) }

// WriteTo must drain buffered tunnel bytes before TCP's optimized copy path.
func (c *bufferedConn) WriteTo(w io.Writer) (int64, error) { return c.reader.WriteTo(w) }

// CloseWrite sends TLS close_notify while allowing the response to be read.
func (c *bufferedConn) CloseWrite() error {
	return c.Conn.(interface{ CloseWrite() error }).CloseWrite()
}

func (c *bufferedConn) CloseRead() error { return c.raw.CloseRead() }
