// Package relaytest exercises TCP idle behavior through each relay's entry point.
package relaytest

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"golang.getoutline.org/sdk/transport"
)

func TCPPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	l, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	a, err := net.DialTCP("tcp4", nil, l.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close() })
	b, err := l.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })
	return a, b
}

func CheckIdle(t *testing.T, connect func(*testing.T, transport.StreamDialer, time.Duration, time.Duration) *net.TCPConn) {
	const limit = 250 * time.Millisecond
	for _, tc := range []struct {
		name                   string
		download, half, active bool
	}{
		{name: "idle"},
		{name: "upload", active: true},
		{name: "download", download: true, active: true},
		{name: "silent response", download: true, half: true},
		{name: "streaming response", download: true, half: true, active: true},
		{name: "silent upload after upstream EOF", half: true},
		{name: "streaming upload after upstream EOF", half: true, active: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream, peer := TCPPair(t)
			dial := transport.FuncStreamDialer(func(context.Context, string) (transport.StreamConn, error) { return upstream, nil })
			idle := limit
			if tc.half {
				idle = time.Hour
			}
			app := connect(t, dial, idle, limit)
			sender, receiver := app, peer
			if tc.download {
				sender, receiver = peer, app
			}
			deadline := time.Now().Add(4 * time.Second)
			for _, c := range []*net.TCPConn{app, peer} {
				if err := c.SetDeadline(deadline); err != nil {
					t.Fatal(err)
				}
			}
			// Establish the flow and a known activity time before measuring inactivity.
			transfer := func() {
				t.Helper()
				if _, err := sender.Write([]byte{'x'}); err != nil {
					t.Fatal(err)
				}
				var b [1]byte
				if _, err := io.ReadFull(receiver, b[:]); err != nil || b[0] != 'x' {
					t.Fatalf("relayed byte %q, error %v", b, err)
				}
			}
			// start precedes the relay's last write, so the measured idle time
			// is never shorter than the real one.
			start := time.Now()
			transfer()
			if tc.half {
				if err := receiver.CloseWrite(); err != nil {
					t.Fatal(err)
				}
				expectEOF(t, sender)
			}
			if tc.active {
				for until := time.Now().Add(2 * limit); time.Now().Before(until); {
					time.Sleep(limit / 8)
					start = time.Now()
					transfer()
				}
			}
			expectEOF(t, receiver)
			if elapsed := time.Since(start); elapsed < limit-25*time.Millisecond {
				t.Fatalf("flow closed after %v, idle limit %v", elapsed, limit)
			}
		})
	}
}

func expectEOF(t *testing.T, c net.Conn) {
	t.Helper()
	var b [1]byte
	if n, err := c.Read(b[:]); n != 0 || err != io.EOF {
		t.Fatalf("expected EOF, got %d bytes and %v", n, err)
	}
}
