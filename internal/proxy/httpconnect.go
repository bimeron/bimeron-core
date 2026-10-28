package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"bimeron/internal/accesskey"
	"golang.getoutline.org/sdk/transport"
)

// HTTPConnect dials TCP destinations through a remote HTTP/1.1 proxy.
type HTTPConnect struct {
	Endpoint accesskey.Endpoint
	Username string
	Dialer   net.Dialer
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
	c := conn.(*net.TCPConn)
	ok := false
	defer func() {
		if !ok {
			_ = c.Close()
		}
	}()
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
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
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP CONNECT rejected (status %d)", response.StatusCode)
	}
	_ = c.SetDeadline(time.Time{})
	ok = true
	if reader.Buffered() != 0 {
		return &bufferedConn{TCPConn: c, reader: reader}, nil
	}
	return c, nil
}

type bufferedConn struct {
	*net.TCPConn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) { return c.reader.Read(b) }
