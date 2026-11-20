package proxy

import (
	"io"
	"net"
	"testing"
	"time"

	"bimeron/internal/relay/relaytest"
	"bimeron/internal/routing"
	"golang.getoutline.org/sdk/transport"
)

func TestRelayIdle(t *testing.T) {
	relaytest.CheckIdle(t, func(t *testing.T, d transport.StreamDialer, idle, half time.Duration) *net.TCPConn {
		p, err := routing.Compile(routing.Config{Default: routing.Proxy})
		if err != nil {
			t.Fatal(err)
		}
		address, _, _ := start(t, &Server{Proxy: d, Policy: p, idle: idle, halfIdle: half})
		c := handshake(t, address, 1)
		var response [10]byte
		if _, err := io.ReadFull(c, response[:]); err != nil || response[1] != 0 {
			t.Fatalf("CONNECT failed: %v %v", response, err)
		}
		return c.(*net.TCPConn)
	})
}
