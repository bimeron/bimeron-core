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
	var payload strings.Builder
	if _, err := io.Copy(&payload, c); err != nil || payload.String() != "hello" {
		t.Fatalf("tunnel bytes: %q, %v", payload.String(), err)
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

func TestBufferedConnectCopyDrainsReader(t *testing.T) {
	c := &bufferedConn{reader: bufio.NewReader(strings.NewReader("buffered tunnel bytes"))}
	var out strings.Builder
	if _, err := io.Copy(&out, c); err != nil || out.String() != "buffered tunnel bytes" {
		t.Fatalf("buffered copy: %q, %v", out.String(), err)
	}
}

func TestHTTPConnectThroughLocalSOCKS(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	serverError := make(chan error, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			serverError <- err
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		r := bufio.NewReader(c)
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				serverError <- err
				return
			}
			if line == "\r\n" {
				break
			}
		}
		_, err = io.WriteString(c, "HTTP/1.1 200 OK\r\n\r\nhello")
		if err != nil {
			serverError <- err
			return
		}
		var ping [4]byte
		_, err = io.ReadFull(r, ping[:])
		if err == nil && string(ping[:]) != "ping" {
			err = fmt.Errorf("unexpected tunnel payload")
		}
		if err == nil {
			_, err = io.WriteString(c, "pong")
		}
		serverError <- err
	}()
	p := &HTTPConnect{Endpoint: accesskey.Endpoint{Host: "127.0.0.1", Port: l.Addr().(*net.TCPAddr).Port}}
	address, _, _ := start(t, &Server{Proxy: p})
	c := handshake(t, address, 1)
	var reply [10]byte
	if _, err := io.ReadFull(c, reply[:]); err != nil || reply[1] != 0 {
		t.Fatalf("SOCKS reply: %v, %v", reply, err)
	}
	if _, err := io.WriteString(c, "ping"); err != nil {
		t.Fatal(err)
	}
	var payload [9]byte
	if _, err := io.ReadFull(c, payload[:]); err != nil || string(payload[:]) != "hellopong" {
		t.Fatalf("relay: %q, %v", payload, err)
	}
	if err := <-serverError; err != nil {
		t.Fatal(err)
	}
}
