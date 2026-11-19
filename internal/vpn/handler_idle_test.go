package vpn

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"bimeron/internal/routing"
	"bimeron/internal/telemetry"

	"golang.getoutline.org/sdk/transport"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// fakeTCPConn is a local TCP socket that reports a netstack destination.
type fakeTCPConn struct {
	*net.TCPConn
	destination net.Addr
}

func (c fakeTCPConn) LocalAddr() net.Addr            { return c.destination }
func (c fakeTCPConn) ID() *stack.TransportEndpointID { return &stack.TransportEndpointID{} }

func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	accepted := make(chan net.Conn, 1)
	go func() { c, _ := l.Accept(); accepted <- c }()
	a, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	b := <-accepted
	if b == nil {
		t.Fatal("accept failed")
	}
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	return a.(*net.TCPConn), b.(*net.TCPConn)
}

// silentUpstream accepts relayed flows, reads whatever arrives and never answers.
func silentUpstream(t *testing.T) transport.StreamDialer {
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

func idleHandler(t *testing.T, idle, halfIdle time.Duration) *Handler {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	h := NewHandler(ctx)
	t.Cleanup(func() { cancel(); h.Close() })
	policy, err := routing.Compile(routing.Config{Default: routing.Direct})
	if err != nil {
		t.Fatal(err)
	}
	h.Policy, h.Stats, h.DirectTCP = policy, &telemetry.Counters{}, silentUpstream(t)
	h.idle, h.halfIdle = idle, halfIdle
	return h
}

func expectReleased(t *testing.T, h *Handler, app net.Conn, within time.Duration) {
	t.Helper()
	_ = app.SetReadDeadline(time.Now().Add(within))
	if _, err := io.Copy(io.Discard, app); err != nil {
		t.Fatal("relay did not close the idle flow:", err)
	}
	deadline := time.Now().Add(within)
	for len(h.slots) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("relay slot was not released")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestHandleTCPClosesIdleFlow(t *testing.T) {
	h := idleHandler(t, 100*time.Millisecond, 50*time.Millisecond)
	app, netstack := tcpPair(t)
	h.HandleTCP(fakeTCPConn{netstack, &net.TCPAddr{IP: net.IPv4(203, 0, 113, 10), Port: 80}})
	expectReleased(t, h, app, 3*time.Second)
}

func TestHandleTCPClosesHalfClosedFlow(t *testing.T) {
	h := idleHandler(t, time.Hour, 100*time.Millisecond)
	app, netstack := tcpPair(t)
	h.HandleTCP(fakeTCPConn{netstack, &net.TCPAddr{IP: net.IPv4(203, 0, 113, 10), Port: 80}})
	if _, err := app.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := app.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	expectReleased(t, h, app, 3*time.Second)
}

func TestHandleTCPKeepsActiveFlow(t *testing.T) {
	h := idleHandler(t, 150*time.Millisecond, 50*time.Millisecond)
	app, netstack := tcpPair(t)
	h.HandleTCP(fakeTCPConn{netstack, &net.TCPAddr{IP: net.IPv4(203, 0, 113, 10), Port: 80}})
	deadline := time.Now().Add(600 * time.Millisecond)
	for time.Now().Before(deadline) {
		if _, err := app.Write([]byte("x")); err != nil {
			t.Fatal("active flow was closed:", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(h.slots) != 1 {
		t.Fatal("active flow lost its slot")
	}
}
