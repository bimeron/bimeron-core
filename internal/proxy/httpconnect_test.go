package proxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"bimeron/internal/accesskey"
)

func TestHTTPConnect(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	requests := make(chan string, 1)
	go func() {
		c, err := listener.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		var request strings.Builder
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			request.WriteString(line)
			if line == "\r\n" {
				break
			}
		}
		requests <- request.String()
		_, _ = io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\nhello")
	}()
	p := HTTPConnect{Endpoint: accesskey.Endpoint{Host: "127.0.0.1", Port: listener.Addr().(*net.TCPAddr).Port, Secret: "secret"}, Username: "alice", Dialer: net.Dialer{Timeout: time.Second}}
	c, err := p.DialStream(context.Background(), "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	b := make([]byte, 5)
	if _, err := io.ReadFull(c, b); err != nil || string(b) != "hello" {
		t.Fatalf("tunnel bytes: %q, %v", b, err)
	}
	request := <-requests
	auth := base64.StdEncoding.EncodeToString([]byte("alice:secret"))
	if !strings.HasPrefix(request, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n") || !strings.Contains(request, "Proxy-Authorization: Basic "+auth+"\r\n") {
		t.Fatalf("invalid CONNECT request: %q", request)
	}
}

func TestHTTPConnectRejectsResponse(t *testing.T) {
	for _, response := range []string{"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n", "HTTP/1.1 200 OK\r\nX: " + strings.Repeat("a", 5000) + "\r\n\r\n"} {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			defer c.Close()
			_, _ = io.WriteString(c, response)
		}()
		p := HTTPConnect{Endpoint: accesskey.Endpoint{Host: "127.0.0.1", Port: listener.Addr().(*net.TCPAddr).Port}, Dialer: net.Dialer{Timeout: time.Second}}
		c, err := p.DialStream(context.Background(), "example.com:443")
		if err == nil {
			_ = c.Close()
			t.Fatal("invalid response accepted")
		}
		_ = listener.Close()
	}
	p := HTTPConnect{}
	if _, err := p.DialStream(context.Background(), fmt.Sprintf("evil\r\nheader: x:%d", 443)); err == nil {
		t.Fatal("invalid target accepted")
	}
}
