package ssplugin

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"bimeron/internal/accesskey"
	"github.com/shadowsocks/go-shadowsocks2/socks"
	"golang.getoutline.org/sdk/transport/shadowsocks"
)

func TestSimpleObfsHTTPDeadlineLifetimeAndCleanup(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	key, err := shadowsocks.NewEncryptionKey("aes-192-gcm", "test-only")
	if err != nil {
		t.Fatal(err)
	}
	requests := make(chan string, 4)
	go func() {
		for {
			raw, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer raw.Close()
				reader := bufio.NewReader(raw)
				var header strings.Builder
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					header.WriteString(line)
					if line == "\r\n" {
						break
					}
				}
				requests <- header.String()
				// An empty response header is valid and need not wait for a reply.
				if _, err := io.WriteString(raw, "HTTP/1.1 101 Switching Protocols\r\n\r\n"); err != nil {
					return
				}
				plain := shadowsocks.NewReader(reader, key)
				if _, err := socks.ReadAddr(plain); err != nil {
					return
				}
				_, _ = io.Copy(shadowsocks.NewWriter(raw, key), plain)
			}()
		}
	}()
	host, portText, _ := net.SplitHostPort(l.Addr().String())
	port, _ := strconv.Atoi(portText)
	settings, err := accesskey.ParseSSPlugin("obfs-local", "obfs=http;obfs-host=cover.example;obfs-uri=/test;http-method=POST")
	if err != nil {
		t.Fatal(err)
	}
	client, err := New(accesskey.Profile{TCP: accesskey.Endpoint{Host: host, Port: port, Cipher: "aes-192-gcm", Secret: "test-only"}, SSPlugin: settings}, net.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithCancel(t.Context())
	conn, err := client.DialStream(ctx, "echo.example:80")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cancel() // The dial context must not own an established connection.
	if err := roundTrip(conn, []byte("AES192 over simple-obfs")); err != nil {
		t.Fatal(err)
	}
	if request := <-requests; !strings.HasPrefix(request, "POST /test HTTP/1.1\r\n") || !strings.Contains(request, "Host: cover.example:"+portText+"\r\n") {
		t.Fatal("incorrect HTTP parameters")
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("connection survived client shutdown")
	}
	client.mu.Lock()
	remaining := len(client.connections)
	client.mu.Unlock()
	if remaining != 0 {
		t.Fatal("connections retained after shutdown")
	}
}

func TestSimpleObfsSetupCancellation(t *testing.T) {
	settings, _ := accesskey.ParseSSPlugin("obfs-local", "obfs=tls")
	p := accesskey.Profile{TCP: accesskey.Endpoint{Host: "127.0.0.1", Port: 1, Cipher: "2022-blake3-aes-128-gcm", Secret: "AAAAAAAAAAAAAAAAAAAAAA=="}, SSPlugin: settings}
	for _, shutdown := range []bool{false, true} {
		entered := make(chan struct{})
		client, err := New(p, net.Dialer{ControlContext: func(ctx context.Context, _, _ string, _ syscall.RawConn) error {
			close(entered)
			<-ctx.Done()
			return ctx.Err()
		}})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() { _, err := client.DialStream(ctx, "echo.example:80"); done <- err }()
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("outbound dialer was not used")
		}
		if shutdown {
			client.Close()
		} else {
			cancel()
		}
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("canceled setup succeeded")
			}
		case <-time.After(time.Second):
			t.Fatal("setup was not interrupted")
		}
		cancel()
		client.Close()
	}
}

func TestSimpleObfsCanceledDial(t *testing.T) {
	settings, _ := accesskey.ParseSSPlugin("obfs-local", "obfs=tls")
	p := accesskey.Profile{TCP: accesskey.Endpoint{Host: "127.0.0.1", Port: 1, Cipher: "aes-256-gcm", Secret: "test-only"}, SSPlugin: settings}
	c, err := New(p, net.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := c.DialStream(ctx, "echo.example:80"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled dial: %v", err)
	}
}
