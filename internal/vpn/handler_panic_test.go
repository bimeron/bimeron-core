package vpn

import (
	"context"
	"net"
	"testing"
	"time"

	"bimeron/internal/guard"
	"bimeron/internal/routing"
	"bimeron/internal/telemetry"

	"golang.getoutline.org/sdk/transport"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type panicNetstackConn struct {
	*net.TCPConn
	destination net.Addr
}

func (c panicNetstackConn) LocalAddr() net.Addr            { return c.destination }
func (c panicNetstackConn) ID() *stack.TransportEndpointID { return &stack.TransportEndpointID{} }

// panickingStream fails like a broken transport adapter on its first write.
type panickingStream struct {
	transport.StreamConn
	unblock <-chan struct{}
}

func (s panickingStream) CloseWrite() error { <-s.unblock; return nil }

func (panickingStream) Write([]byte) (int, error) { panic("transport write") }

func loopbackPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
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

// A panic in a relay goroutine must not block the handler shutdown that the
// session's crash cleanup performs.
func TestRelayPanicDoesNotBlockHandlerClose(t *testing.T) {
	rethrown := make(chan any, 1)
	defer guard.SetRethrow(func(p any) { rethrown <- p })()

	unblock := make(chan struct{})
	defer close(unblock)
	upstreamApp, _ := loopbackPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h := NewHandler(ctx)
	policy, err := routing.Compile(routing.Config{Default: routing.Direct})
	if err != nil {
		t.Fatal(err)
	}
	h.Policy, h.Stats = policy, &telemetry.Counters{}
	h.DirectTCP = transport.FuncStreamDialer(func(context.Context, string) (transport.StreamConn, error) {
		return panickingStream{upstreamApp, unblock}, nil
	})

	closed := make(chan struct{})
	unregister := guard.Register(func(any) <-chan struct{} {
		go func() { h.Close(); close(closed) }()
		return closed
	})
	defer unregister()

	app, netstack := loopbackPair(t)
	h.HandleTCP(panicNetstackConn{netstack, &net.TCPAddr{IP: net.IPv4(203, 0, 113, 10), Port: 80}})
	if _, err := app.Write([]byte("data")); err != nil {
		t.Fatal(err)
	}
	select {
	case p := <-rethrown:
		if p != "transport write" {
			t.Fatal(p)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handler close blocked on the panicking relay")
	}
	select {
	case <-closed:
	default:
		t.Fatal("rethrown before cleanup finished")
	}
}

type panicDownloadStream struct {
	transport.StreamConn
	unblock <-chan struct{}
}

func (panicDownloadStream) Read([]byte) (int, error) { panic("download read") }
func (s panicDownloadStream) Close() error           { <-s.unblock; return s.StreamConn.Close() }

func TestDownloadPanicWithBlockedUpstreamClose(t *testing.T) {
	unblock := make(chan struct{})
	defer close(unblock)
	rethrown := make(chan any, 1)
	defer guard.SetRethrow(func(p any) { rethrown <- p })()

	upstream, _ := loopbackPair(t)
	h := NewHandler(context.Background())
	t.Cleanup(h.Close)
	h.TCP = transport.FuncStreamDialer(func(context.Context, string) (transport.StreamConn, error) {
		return panicDownloadStream{upstream, unblock}, nil
	})
	_, client := loopbackPair(t)
	h.HandleTCP(panicNetstackConn{client, &net.TCPAddr{IP: net.IPv4(203, 0, 113, 10), Port: 80}})
	select {
	case p := <-rethrown:
		if p != "download read" {
			t.Fatal(p)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("upstream close blocked panic dispatch")
	}
}

type panicPacket struct {
	net.PacketConn
	release chan struct{}
}

func (p panicPacket) ListenPacket(context.Context) (net.PacketConn, error) { return p, nil }
func (p panicPacket) WriteTo([]byte, net.Addr) (int, error)                { panic("UDP write") }
func (p panicPacket) Close() error                                         { <-p.release; return p.PacketConn.Close() }

type udpFlow struct{ *net.UDPConn }

func (udpFlow) ID() *stack.TransportEndpointID { return &stack.TransportEndpointID{} }

func TestUDPWritePanicWithBlockedUpstreamClose(t *testing.T) {
	upstream, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	packet := panicPacket{upstream, release}
	rethrown := make(chan any, 1)
	defer guard.SetRethrow(func(p any) { rethrown <- p })()
	defer close(release)

	h := NewHandler(context.Background())
	t.Cleanup(h.Close)
	h.UDP = packet
	flow, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	h.HandleUDP(udpFlow{flow})
	client, err := net.DialUDP("udp4", nil, flow.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_, err = client.Write([]byte("data"))

	if err != nil {
		t.Fatal(err)
	}
	select {
	case p := <-rethrown:
		if p != "UDP write" {
			t.Fatal(p)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("blocked upstream close prevented panic dispatch")
	}
}
