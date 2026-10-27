package hysteria2

import (
	"errors"
	"net"
	"testing"
	"time"
)

type fakeUDP struct {
	incoming chan packet
	closed   chan struct{}
}

func (f *fakeUDP) Receive() ([]byte, string, error) {
	select {
	case p := <-f.incoming:
		return p.data, p.addr, p.err
	case <-f.closed:
		return nil, "", net.ErrClosed
	}
}
func (*fakeUDP) Send([]byte, string) error { return nil }
func (f *fakeUDP) Close() error {
	select {
	case <-f.closed:
	default:
		close(f.closed)
	}
	return nil
}

func TestPacketDeadlineAndClose(t *testing.T) {
	u := &fakeUDP{incoming: make(chan packet), closed: make(chan struct{})}
	p := &packetConn{upstream: u, changed: make(chan struct{}), done: make(chan struct{}), incoming: make(chan packet, 1)}
	go p.receive()
	if err := p.SetReadDeadline(time.Now().Add(10 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	_, _, err := p.ReadFrom(make([]byte, 16))
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("expected timeout, got %v", err)
	}
	if err := p.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	u.incoming <- packet{data: []byte("ok"), addr: "127.0.0.1:53"}
	b := make([]byte, 16)
	n, addr, err := p.ReadFrom(b)
	if err != nil || string(b[:n]) != "ok" || addr.String() != "127.0.0.1:53" {
		t.Fatalf("packet: %q %v %v", b[:n], addr, err)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	_, _, err = p.ReadFrom(b)
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("expected closed connection, got %v", err)
	}
}
