package proxy

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/transport/shadowsocks"
	"bimeron/internal/accesskey"
	"bimeron/internal/routing"
	"bimeron/internal/telemetry"
)

func start(t *testing.T, s *Server) (string, context.CancelFunc, <-chan error) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, l) }()
	t.Cleanup(cancel)
	return l.Addr().String(), cancel, done
}
func handshake(t *testing.T, address string, command byte) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = c.Write([]byte{5, 1, 0})
	if err != nil {
		t.Fatal(err)
	}
	var method [2]byte
	if _, err = io.ReadFull(c, method[:]); err != nil || method != [2]byte{5, 0} {
		t.Fatalf("greeting: %v %v", method, err)
	}
	_, err = c.Write([]byte{5, command, 0, 1, 203, 0, 113, 10, 0, 80})
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func TestEncryptedRelayAndShutdown(t *testing.T) {
	keepOpen := make(chan struct{})
	defer close(keepOpen)
	// A local Shadowsocks endpoint verifies the request is encrypted and the target
	// address is passed inside the encrypted stream before the application payload.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	key, err := shadowsocks.NewEncryptionKey("aes-256-gcm", "test-only-secret")
	if err != nil {
		t.Fatal(err)
	}
	received := make(chan error, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			received <- err
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		r := shadowsocks.NewReader(c, key)
		w := shadowsocks.NewWriter(c, key)
		var target [7]byte
		if _, err = io.ReadFull(r, target[:]); err != nil {
			received <- err
			return
		}
		if target != [7]byte{1, 203, 0, 113, 10, 0, 80} {
			received <- io.ErrUnexpectedEOF
			return
		}
		var payload [4]byte
		if _, err = io.ReadFull(r, payload[:]); err != nil {
			received <- err
			return
		}
		if string(payload[:]) != "ping" {
			received <- io.ErrUnexpectedEOF
			return
		}
		_, err = w.Write([]byte("pong"))
		received <- err
		<-keepOpen
	}()
	tcp := l.Addr().(*net.TCPAddr)
	d, err := Outline(accesskey.Endpoint{Host: "127.0.0.1", Port: tcp.Port, Cipher: "aes-256-gcm", Secret: "test-only-secret", Prefix: "GET "})
	if err != nil {
		t.Fatal(err)
	}
	stats := &telemetry.Counters{}
	address, cancel, done := start(t, &Server{Proxy: d, Stats: stats})
	c := handshake(t, address, 1)
	var response [10]byte
	if _, err = io.ReadFull(c, response[:]); err != nil || response[1] != 0 {
		t.Fatalf("CONNECT failed: %v", err)
	}
	if _, err = c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	var data [4]byte
	if _, err = io.ReadFull(c, data[:]); err != nil || string(data[:]) != "pong" {
		t.Fatalf("relay: %q %v", data, err)
	}
	if err := <-received; err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		snapshot := stats.Snapshot()
		if snapshot.BytesUp == 4 && snapshot.BytesDown == 4 && snapshot.TCPActive == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("open SOCKS stream statistics stale", snapshot)
		}
		time.Sleep(time.Millisecond)
	}
	// Also keep an unfinished SOCKS greeting open to verify shutdown does not hang.
	idle, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer idle.Close()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown hung")
	}
}
func TestBlockAndUnsupportedUDP(t *testing.T) {
	p, err := routing.Compile(routing.Config{Default: routing.Block})
	if err != nil {
		t.Fatal(err)
	}
	address, _, _ := start(t, &Server{Proxy: &transport.TCPDialer{}, Policy: p})
	for _, tc := range []struct{ command, reply byte }{{1, 2}, {3, 7}} {
		c := handshake(t, address, tc.command)
		var b [10]byte
		if _, err := io.ReadFull(c, b[:]); err != nil || b[1] != tc.reply {
			t.Fatalf("reply: %v, %v", b, err)
		}
		_ = c.Close()
	}
}
func TestDirectRelay(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		c, err := echo.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.Copy(c, c)
	}()
	p, _ := routing.Compile(routing.Config{Default: routing.Direct})
	never := transport.FuncStreamDialer(func(context.Context, string) (transport.StreamConn, error) {
		t.Error("proxy dialed for direct rule")
		return nil, io.ErrUnexpectedEOF
	})
	address, _, _ := start(t, &Server{Proxy: never, Policy: p})
	c, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = c.Write([]byte{5, 1, 0})
	var method [2]byte
	_, _ = io.ReadFull(c, method[:])
	port := echo.Addr().(*net.TCPAddr).Port
	_, _ = c.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1, byte(port >> 8), byte(port)})
	var response [10]byte
	if _, err = io.ReadFull(c, response[:]); err != nil || response[1] != 0 {
		t.Fatal("direct CONNECT failed")
	}
	_, _ = c.Write([]byte("ping"))
	var payload [4]byte
	if _, err = io.ReadFull(c, payload[:]); err != nil || string(payload[:]) != "ping" {
		t.Fatalf("direct relay: %v", err)
	}
}
