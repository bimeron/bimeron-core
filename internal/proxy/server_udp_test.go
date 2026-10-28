package proxy

import (
	"context"
	"errors"
	"net"
	"os"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"bimeron/internal/accesskey"
	"bimeron/internal/routing"
	"golang.getoutline.org/sdk/transport"
)

type resolvedPackets struct{ writes atomic.Int32 }

func (r *resolvedPackets) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	return &resolvedPacket{PacketConn: c, owner: r}, nil
}

type resolvedPacket struct {
	net.PacketConn
	owner *resolvedPackets
}

func (p *resolvedPacket) WriteTo(b []byte, a net.Addr) (int, error) {
	target, err := net.ResolveUDPAddr("udp", a.String())
	if err != nil {
		return 0, err
	}
	p.owner.writes.Add(1)
	return p.PacketConn.WriteTo(b, target)
}

func TestSOCKSUDPPolicyAndSourcePinning(t *testing.T) {
	target, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		b := make([]byte, 2048)
		for {
			n, a, err := target.ReadFrom(b)
			if err != nil {
				return
			}
			_, _ = target.WriteTo(b[:n], a)
		}
	}()
	for _, action := range []routing.Action{routing.Proxy, routing.Direct, routing.Block} {
		t.Run(string(action), func(t *testing.T) {
			packets := &resolvedPackets{}
			policy, err := routing.Compile(routing.Config{Default: action})
			if err != nil {
				t.Fatal(err)
			}
			address, cancel, done := start(t, &Server{Proxy: &transport.TCPDialer{}, Packet: packets, Policy: policy})
			defer func() {
				cancel()
				select {
				case err := <-done:
					if err != nil {
						t.Error(err)
					}
				case <-time.After(time.Second):
					t.Error("UDP association prevented shutdown")
				}
			}()
			host, portText, _ := net.SplitHostPort(address)
			port, _ := strconv.Atoi(portText)
			socks := &SOCKS5{Endpoint: accesskey.Endpoint{Host: host, Port: port}}
			conn, err := socks.ListenPacket(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			p := conn.(*socksPacketConn)
			destination := target.LocalAddr()
			_ = p.SetDeadline(time.Now().Add(time.Second))
			if _, err := p.WriteTo([]byte("allowed"), destination); err != nil {
				t.Fatal(err)
			}
			b := make([]byte, 64)
			if action == routing.Block {
				_ = p.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
				if _, _, err := p.ReadFrom(b); !errors.Is(err, os.ErrDeadlineExceeded) {
					t.Fatal(err)
				}
				if packets.writes.Load() != 0 {
					t.Fatal("blocked datagram reached upstream")
				}
				return
			}
			if n, from, err := p.ReadFrom(b); err != nil || string(b[:n]) != "allowed" || from.String() != destination.String() {
				t.Fatalf("policy relay: %v", err)
			}
			if (packets.writes.Load() != 0) != (action == routing.Proxy) {
				t.Fatal("wrong UDP route")
			}
			encoded, err := socksAddress(destination.String())
			if err != nil {
				t.Fatal(err)
			}
			frame := append([]byte{0, 0, 0}, encoded...)
			frame = append(frame, []byte("spoofed")...)
			attacker, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer attacker.Close()
			if _, err := attacker.WriteTo(frame, p.relay); err != nil {
				t.Fatal(err)
			}
			// SOCKS fragmentation is unsupported and must never be forwarded.
			frame[2] = 1
			if _, err := p.PacketConn.WriteTo(frame, p.relay); err != nil {
				t.Fatal(err)
			}
			_ = p.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
			if _, _, err := p.ReadFrom(b); !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatal("spoofed or fragmented datagram accepted", err)
			}
			if action == routing.Proxy && packets.writes.Load() != 1 {
				t.Fatal("invalid datagram reached upstream")
			}
			// Leave the association open: server cancellation must release all workers.
		})
	}
}
