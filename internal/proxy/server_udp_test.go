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

// domainPackets emulates a proxy server that resolves every domain target to
// loopback, so replies come back from an IP source.
type domainPackets struct{}

func (domainPackets) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	return domainPacket{c}, nil
}

type domainPacket struct{ net.PacketConn }

func (p domainPacket) WriteTo(b []byte, a net.Addr) (int, error) {
	_, port, err := net.SplitHostPort(a.String())
	if err != nil {
		return 0, err
	}
	target, err := net.ResolveUDPAddr("udp", net.JoinHostPort("127.0.0.1", port))
	if err != nil {
		return 0, err
	}
	return p.PacketConn.WriteTo(b, target)
}

func udpEcho(t *testing.T) net.PacketConn {
	t.Helper()
	target, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = target.Close() })
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
	return target
}

func socksUDP(t *testing.T, s *Server) *socksPacketConn {
	t.Helper()
	address, cancel, _ := start(t, s)
	t.Cleanup(cancel)
	host, portText, _ := net.SplitHostPort(address)
	port, _ := strconv.Atoi(portText)
	conn, err := (&SOCKS5{Endpoint: accesskey.Endpoint{Host: host, Port: port}}).ListenPacket(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn.(*socksPacketConn)
}

func TestSOCKSUDPProxiedDomainReply(t *testing.T) {
	target := udpEcho(t)
	p := socksUDP(t, &Server{Proxy: &transport.TCPDialer{}, Packet: domainPackets{}})
	_, port, _ := net.SplitHostPort(target.LocalAddr().String())
	_ = p.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := p.WriteTo([]byte("domain"), udpTarget(net.JoinHostPort("echo.invalid", port))); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 64)
	if n, _, err := p.ReadFrom(b); err != nil || string(b[:n]) != "domain" {
		t.Fatalf("domain reply: %q, %v", b[:n], err)
	}
}

func TestSOCKSUDPEvictsIdleDestinations(t *testing.T) {
	policy, err := routing.Compile(routing.Config{Default: routing.Direct})
	if err != nil {
		t.Fatal(err)
	}
	p := socksUDP(t, &Server{Proxy: &transport.TCPDialer{}, Packet: &resolvedPackets{}, Policy: policy})
	b := make([]byte, 64)
	for i := range maxUDPPeers + 6 {
		destination := udpEcho(t).LocalAddr()
		_ = p.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := p.WriteTo([]byte("ping"), destination); err != nil {
			t.Fatal(err)
		}
		if n, from, err := p.ReadFrom(b); err != nil || string(b[:n]) != "ping" || from.String() != destination.String() {
			t.Fatalf("destination %d: %q, %v, %v", i, b[:n], from, err)
		}
	}
}

func TestUDPPeersLeastRecentlyUsedEviction(t *testing.T) {
	peers := newUDPPeers()
	for i := range maxUDPPeers {
		peers.add(strconv.Itoa(i), routing.Direct, false)
	}
	peers.add("0", routing.Direct, false) // refresh the oldest entry
	peers.add("new", routing.Direct, false)
	if !peers.allows("0", routing.Direct) || peers.allows("1", routing.Direct) || !peers.allows("new", routing.Direct) {
		t.Fatal("least recently used destination was not evicted")
	}
	if peers.allows("new", routing.Proxy) {
		t.Fatal("reply accepted through a different route")
	}
	peers.add("echo.invalid:53", routing.Proxy, true)
	if !peers.allows("192.0.2.1:53", routing.Proxy) || peers.allows("192.0.2.1:53", routing.Direct) {
		t.Fatal("proxied domain reply filtering")
	}
	for i := range maxUDPPeers {
		peers.add("evict"+strconv.Itoa(i), routing.Direct, false)
	}
	if peers.domains != 0 || peers.allows("192.0.2.1:53", routing.Proxy) {
		t.Fatal("evicted domain destination still accepted")
	}
}
