package wireguard

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"bimeron/internal/wgconf"
	"bimeron/internal/wireguard/wgtest"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
)

// outsideEcho runs TCP and UDP echo on 127.0.0.1, outside any tunnel.
func outsideEcho(t *testing.T) (tcp, udp netip.AddrPort) {
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
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], from)
		}
	}()
	return l.Addr().(*net.TCPAddr).AddrPort(), pc.LocalAddr().(*net.UDPAddr).AddrPort()
}

func TestCloseEndsDirectSocketsAndStreams(t *testing.T) {
	client := wgtest.NewKeyPair(t)
	s := wgtest.StartAWG(t, client, nil)
	tcpAddr, udpAddr := outsideEcho(t)
	c := startClient(t, s.ClientText(client, "10.77.0.0/24"), ModeDirect)
	stream, err := c.DialStream(context.Background(), tcpAddr.String())
	if err != nil {
		t.Fatal(err)
	}
	pc, err := c.ListenPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pc.WriteTo([]byte("x"), net.UDPAddrFromAddrPort(udpAddr)); err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	_ = stream.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := stream.Read(make([]byte, 1)); err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("direct stream survived Close: %v", err)
	}
	_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		_, _, err := pc.ReadFrom(make([]byte, 16))
		if errors.Is(err, net.ErrClosed) {
			break
		}
		if err != nil {
			t.Fatalf("packet socket survived Close: %v", err)
		}
	}
	if _, err := pc.WriteTo([]byte("x"), net.UDPAddrFromAddrPort(udpAddr)); err == nil {
		t.Fatal("closed generation opened a new direct socket")
	}
	if _, err := c.ListenPacket(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatal("ListenPacket after Close")
	}
}

func TestReadDeadlineWakesAllReaders(t *testing.T) {
	client := wgtest.NewKeyPair(t)
	s := wgtest.StartAWG(t, client, nil)
	c := startClient(t, s.ClientText(client, "10.77.0.0/24"), ModeDirect)
	pc, _ := c.ListenPacket(context.Background())
	defer pc.Close()
	var wg sync.WaitGroup
	errs := make(chan error, 3)
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, _, err := pc.ReadFrom(make([]byte, 8)); errs <- err }()
	}
	time.Sleep(100 * time.Millisecond)
	_ = pc.SetReadDeadline(time.Now())
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("a reader missed the deadline change")
	}
}

func TestDNSFailoverToSecondResolver(t *testing.T) {
	client := wgtest.NewKeyPair(t)
	s := wgtest.StartAWG(t, client, nil)
	wgtest.StartDNS(t, s, "echo.test.", wgtest.ServerV4)
	// 10.77.0.9 is inside the tunnel but silent.
	c := startClient(t, s.ClientText(client, "10.77.0.0/24"), ModeBlock, "10.77.0.9", wgtest.ServerV4.String())
	start := time.Now()
	echoTCP(t, c, "echo.test:7", 128)
	if time.Since(start) > 6*time.Second {
		t.Fatal("failover took too long")
	}
}

func TestTunnelFamilyWithoutAddress(t *testing.T) {
	client := wgtest.NewKeyPair(t)
	s := wgtest.StartAWG(t, client, nil)
	text := strings.Replace(s.ClientText(client, "0.0.0.0/0, ::/0"), ", "+wgtest.ClientV6.String()+"/128", "", 1)
	c := startClient(t, text, ModeDirect)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := c.DialStream(ctx, "[fd77::1]:7"); err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("IPv6 dial without a tunnel IPv6 address: %v", err)
	}
	echoTCP(t, c, "10.77.0.1:7", 64)
}

func TestProbeForcesNewHandshake(t *testing.T) {
	client := wgtest.NewKeyPair(t)
	s := wgtest.StartAWG(t, client, nil)
	c := startClient(t, s.ClientText(client, "10.77.0.0/24"), "")
	first := c.LastHandshake()
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	// The engine allows a new initiation after its rekey timeout.
	if err := c.waitHandshakeAfter(ctx, first); err != nil {
		t.Fatal(err)
	}
	if c.LastHandshake().Equal(first) {
		t.Fatal("handshake time did not change")
	}
}

func TestEndpointAndExclusivePort(t *testing.T) {
	client := wgtest.NewKeyPair(t)
	s := wgtest.StartAWG(t, client, nil)
	text := strings.Replace(s.ClientText(client, "10.77.0.0/24"), "[Peer]", "ListenPort = 0\n[Peer]", 1)
	c := startClient(t, text, "")
	if c.Endpoint() != s.Addr || c.ExclusivePort() {
		t.Fatalf("endpoint %v exclusive %v", c.Endpoint(), c.ExclusivePort())
	}
}

func TestPlatformPacketLimit(t *testing.T) {
	client := wgtest.NewKeyPair(t)
	s := wgtest.StartAWG(t, client, nil)
	cfg, err := wgconf.Parse(strings.Replace(s.ClientText(client, "10.77.0.0/24"), "[Peer]", "Jc = 1\nJmin = 10\nJmax = 4000\n[Peer]", 1))
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(Options{Config: cfg, Endpoint: s.Addr})
	if device.MaxMessageSize < 4000 {
		if !errors.Is(err, ErrPlatformLimit) {
			t.Fatalf("want ErrPlatformLimit, got %v", err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
}
