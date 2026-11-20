package vpn

import (
	"context"
	"net"
	"testing"
	"time"

	"bimeron/internal/relay/relaytest"
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

func TestHandleTCPIdle(t *testing.T) {
	relaytest.CheckIdle(t, func(t *testing.T, d transport.StreamDialer, idle, half time.Duration) *net.TCPConn {
		h := NewHandler(context.Background())
		t.Cleanup(h.Close)
		p, err := routing.Compile(routing.Config{Default: routing.Direct})
		if err != nil {
			t.Fatal(err)
		}
		h.Policy, h.Stats, h.DirectTCP = p, &telemetry.Counters{}, d
		h.idle, h.halfIdle = idle, half
		app, stackConn := relaytest.TCPPair(t)
		h.HandleTCP(fakeTCPConn{stackConn, &net.TCPAddr{IP: net.IPv4(203, 0, 113, 10), Port: 80}})
		t.Cleanup(func() {
			deadline := time.Now().Add(time.Second)
			for len(h.slots) != 0 {
				if time.Now().After(deadline) {
					t.Error("relay slot was not released")
					return
				}
				time.Sleep(5 * time.Millisecond)
			}
		})
		return app
	})
}

func TestHandleTCPClosedUpstreamReleasesSilentLocal(t *testing.T) {
	upstream, _ := relaytest.TCPPair(t)
	if err := upstream.Close(); err != nil {
		t.Fatal(err)
	}
	_, local := relaytest.TCPPair(t)
	h := NewHandler(context.Background())
	t.Cleanup(h.Close)
	h.idle, h.halfIdle = time.Hour, time.Hour
	h.TCP = transport.FuncStreamDialer(func(context.Context, string) (transport.StreamConn, error) {
		return upstream, nil
	})
	h.HandleTCP(fakeTCPConn{local, &net.TCPAddr{IP: net.IPv4(203, 0, 113, 10), Port: 80}})
	done := make(chan struct{})
	go func() {
		h.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("handler remained blocked after upstream closed while local socket was silent")
	}
}
