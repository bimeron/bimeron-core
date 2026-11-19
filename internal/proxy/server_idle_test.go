package proxy

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"bimeron/internal/routing"
	"golang.getoutline.org/sdk/transport"
)

// silentProxy relays every CONNECT to a listener that reads and never answers.
func silentProxy(t *testing.T) transport.StreamDialer {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(io.Discard, c) }()
		}
	}()
	dialer := &transport.TCPDialer{}
	return transport.FuncStreamDialer(func(ctx context.Context, _ string) (transport.StreamConn, error) {
		return dialer.DialStream(ctx, l.Addr().String())
	})
}

func connectSilent(t *testing.T, idle, halfIdle time.Duration) net.Conn {
	t.Helper()
	p, err := routing.Compile(routing.Config{Default: routing.Proxy})
	if err != nil {
		t.Fatal(err)
	}
	address, _, _ := start(t, &Server{Proxy: silentProxy(t), Policy: p, idle: idle, halfIdle: halfIdle})
	c := handshake(t, address, 1)
	var response [10]byte
	if _, err := io.ReadFull(c, response[:]); err != nil || response[1] != 0 {
		t.Fatalf("CONNECT failed: %v %v", response, err)
	}
	return c
}

func expectClosed(t *testing.T, c net.Conn, within time.Duration) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(within))
	if _, err := io.Copy(io.Discard, c); err != nil {
		t.Fatal("idle relay was not closed:", err)
	}
}

func TestRelayClosesIdleFlow(t *testing.T) {
	c := connectSilent(t, 100*time.Millisecond, 50*time.Millisecond)
	expectClosed(t, c, 3*time.Second)
}

func TestRelayClosesHalfClosedFlow(t *testing.T) {
	c := connectSilent(t, time.Hour, 100*time.Millisecond)
	if _, err := c.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := c.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	expectClosed(t, c, 3*time.Second)
}

func TestRelayKeepsActiveFlow(t *testing.T) {
	c := connectSilent(t, 150*time.Millisecond, 50*time.Millisecond)
	deadline := time.Now().Add(600 * time.Millisecond)
	for time.Now().Before(deadline) {
		if _, err := c.Write([]byte("x")); err != nil {
			t.Fatal("active relay was closed:", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	_ = c.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	if _, err := c.Read(make([]byte, 1)); err == nil || !isTimeout(err) {
		t.Fatal("active relay was closed:", err)
	}
}

func isTimeout(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}
