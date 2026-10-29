package masque

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestConnectionClosedBeforeSetupCancellation(t *testing.T) {
	for _, closed := range []bool{false, true} {
		for _, busy := range []bool{false, true} {
			clientCtx, closeClient := context.WithCancel(context.Background())
			c := &Client{ctx: clientCtx, closed: closed, connecting: make(chan struct{}, 1)}
			if closed {
				closeClient()
			}
			// Keep live-client cancellation socket-free by blocking admission.
			if busy || !closed {
				c.connecting <- struct{}{}
			}
			setup, cancel := context.WithCancel(context.Background())
			cancel()
			want := context.Canceled
			if closed {
				want = net.ErrClosed
			}
			for i := 0; i < 100; i++ {
				conn, err := c.connection(setup)
				if conn != nil || !errors.Is(err, want) {
					t.Fatalf("closed=%v busy=%v: connection = %v, %v; want nil, %v", closed, busy, conn, err, want)
				}
			}
			closeClient()
		}
	}
}
