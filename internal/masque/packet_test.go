package masque

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"bimeron/internal/accesskey"
)

func TestPacketLimitsAndDeadlineChanges(t *testing.T) {
	profile, err := accesskey.ParseMASQUE("masque://127.0.0.1:9")
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(profile, net.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	packet, err := c.ListenPacket(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	p := packet.(*packetConn)
	// A live blocked read must observe new deadlines and recover after a timeout.
	done := make(chan error, 1)
	go func() { _, _, err := p.ReadFrom(make([]byte, 32)); done <- err }()
	if err := p.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked read ignored deadline")
	}
	_ = p.SetReadDeadline(time.Time{})
	p.incoming <- datagram{data: []byte("x"), from: packetAddr("127.0.0.1:53")}
	if n, _, err := p.ReadFrom(make([]byte, 32)); n != 1 || err != nil {
		t.Fatal(n, err)
	}
	p.mu.Lock()
	for i := range maxDestinations {
		p.sessions[fmt.Sprint(i)] = &tunnel{}
	}
	p.mu.Unlock()
	if n, err := p.WriteTo([]byte("x"), packetAddr("127.0.0.1:53")); n != 0 || err == nil {
		t.Fatal("destination limit ignored")
	}
	p.mu.Lock()
	clear(p.sessions)
	p.mu.Unlock()
	for range maxTunnels {
		c.slots <- struct{}{}
	}
	if _, err := c.DialStream(t.Context(), "127.0.0.1:53"); err == nil {
		t.Fatal("global tunnel limit ignored")
	}
	for range maxTunnels {
		<-c.slots
	}
	// Including p, only 128 packet listeners can own queues and reaper goroutines.
	for range 127 {
		if _, err := c.ListenPacket(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.ListenPacket(t.Context()); err == nil {
		t.Fatal("packet listener limit ignored")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if len(c.packets) != 0 {
		t.Fatal("packet listeners leaked")
	}
}

func TestDatagramBackpressureHonorsCancellation(t *testing.T) {
	// Model an unavailable sender without a socket or timing-dependent QUIC load.
	c := &Client{ctx: t.Context(), outgoing: make(chan datagramWrite, 1)}
	c.outgoing <- datagramWrite{}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if err := c.sendDatagram(ctx, nil, []byte("full queue")); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	<-c.outgoing
	ctx2, cancel2 := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel2()
	if err := c.sendDatagram(ctx2, nil, []byte("blocked sender")); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	queued := <-c.outgoing
	// A worker can report an eventual outcome after the caller has timed out.
	queued.result <- nil
}
