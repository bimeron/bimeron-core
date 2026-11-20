package wireguard

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"bimeron/internal/wgconf"
	"bimeron/internal/wireguard/wgtest"
)

func startClient(t testing.TB, text, mode string, dns ...string) *Client {
	t.Helper()
	cfg, err := wgconf.Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := netip.MustParseAddrPort(cfg.Endpoint())
	c, err := New(Options{Config: cfg, Endpoint: endpoint, Mode: mode, DNS: dns})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := c.WaitHandshake(ctx); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	return c
}

func echoTCP(t testing.TB, c *Client, to string, size int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := c.DialStream(ctx, to)
	if err != nil {
		t.Fatalf("dial %s: %v", to, err)
	}
	defer conn.Close()
	payload := make([]byte, size)
	_, _ = rand.Read(payload)
	go func() { _, _ = conn.Write(payload); _ = conn.CloseWrite() }()
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	got, err := io.ReadAll(conn)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("tcp echo %s: %d/%d bytes, %v", to, len(got), size, err)
	}
}

func echoUDP(t testing.TB, c *Client, to netip.AddrPort, size int) {
	t.Helper()
	pc, err := c.ListenPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	payload := make([]byte, size)
	_, _ = rand.Read(payload)
	buf := make([]byte, 65535)
	for attempt := 0; attempt < 5; attempt++ {
		if _, err := pc.WriteTo(payload, net.UDPAddrFromAddrPort(to)); err != nil {
			t.Fatal(err)
		}
		_ = pc.SetReadDeadline(time.Now().Add(time.Second))
		n, from, err := pc.ReadFrom(buf)
		if err == nil && bytes.Equal(buf[:n], payload) && from.(*net.UDPAddr).AddrPort() == to {
			return
		}
	}
	t.Fatalf("udp echo %s with %d bytes failed", to, size)
}

func TestUpstreamWireGuardInterop(t *testing.T) {
	client := wgtest.NewKeyPair(t)
	s := wgtest.StartUpstream(t, client)
	c := startClient(t, s.ClientText(client, "0.0.0.0/0, ::/0"), "")
	if c.LastHandshake().IsZero() {
		t.Fatal("no handshake time")
	}
	echoTCP(t, c, "10.77.0.1:7", 256<<10)
	echoTCP(t, c, "[fd77::1]:7", 64<<10)
	echoUDP(t, c, netip.MustParseAddrPort("10.77.0.1:7"), 1200)
	echoUDP(t, c, netip.MustParseAddrPort("[fd77::1]:7"), 1200)
	// Larger than the tunnel MTU: the inner stack fragments the datagram.
	echoUDP(t, c, netip.MustParseAddrPort("10.77.0.1:7"), 8000)
	sent, received := c.Traffic()
	if sent == 0 || received == 0 {
		t.Fatal("no encrypted traffic counted")
	}
}

func TestAmneziaWGVersions(t *testing.T) {
	for name, p := range wgtest.Profiles {
		t.Run(name, func(t *testing.T) {
			client := wgtest.NewKeyPair(t)
			s := wgtest.StartAWG(t, client, p.Server)
			c := startClient(t, s.ClientText(client, "0.0.0.0/0, ::/0", p.Client...), "")
			echoTCP(t, c, "10.77.0.1:7", 128<<10)
			echoUDP(t, c, netip.MustParseAddrPort("[fd77::1]:7"), 1000)
		})
	}
}

func TestPlainClientAgainstAWGServerWithoutOptions(t *testing.T) {
	client := wgtest.NewKeyPair(t)
	s := wgtest.StartAWG(t, client, nil)
	c := startClient(t, s.ClientText(client, "10.77.0.0/24"), "")
	echoTCP(t, c, "10.77.0.1:7", 4096)
}

func TestHandshakeFailsWithWrongServerKey(t *testing.T) {
	client := wgtest.NewKeyPair(t)
	s := wgtest.StartAWG(t, client, nil)
	s.Key = wgtest.NewKeyPair(t)
	cfg, err := wgconf.Parse(s.ClientText(client, "0.0.0.0/0"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(Options{Config: cfg, Endpoint: s.Addr})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	if err := c.WaitHandshake(ctx); err == nil {
		t.Fatal("handshake with a wrong key must not complete")
	}
}

func TestAWGMismatchFailsHandshake(t *testing.T) {
	client := wgtest.NewKeyPair(t)
	s := wgtest.StartAWG(t, client, wgtest.Profiles["awg-2.0"].Server)
	cfg, _ := wgconf.Parse(s.ClientText(client, "0.0.0.0/0"))
	c, err := New(Options{Config: cfg, Endpoint: s.Addr})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	if err := c.WaitHandshake(ctx); err == nil {
		t.Fatal("plain WireGuard must not reach an obfuscated server")
	}
}

func TestAllowedIPsScope(t *testing.T) {
	client := wgtest.NewKeyPair(t)
	s := wgtest.StartAWG(t, client, nil)
	// A direct echo service outside the tunnel on loopback.
	outside, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer outside.Close()
	go func() {
		for {
			conn, err := outside.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()
	text := s.ClientText(client, "10.77.0.0/24")
	direct := startClient(t, text, ModeDirect)
	echoTCP(t, direct, "10.77.0.1:7", 1024)
	echoTCP(t, direct, outside.Addr().String(), 1024)
	if direct.scope(netip.MustParseAddr("2001:db8::1")) != viaDirect {
		t.Fatal("partial IPv4 coverage must not block IPv6")
	}

	block := startClient(t, text, ModeBlock)
	ctx := context.Background()
	if _, err := block.DialStream(ctx, outside.Addr().String()); !errors.Is(err, ErrBlocked) {
		t.Fatalf("block mode dialed outside AllowedIPs: %v", err)
	}
	echoTCP(t, block, "10.77.0.1:7", 1024)

	ignore := startClient(t, s.ClientText(client, "10.77.0.0/30"), ModeIgnore)
	if ignore.scope(netip.MustParseAddr("192.0.2.1")) != viaTunnel {
		t.Fatal("ignore mode must tunnel everything")
	}

	guard := startClient(t, s.ClientText(client, "0.0.0.0/0"), ModeDirect)
	if guard.scope(netip.MustParseAddr("2001:db8::1")) != blocked || guard.scope(netip.MustParseAddr("fd77::1")) != blocked {
		t.Fatal("IPv4-only coverage must block IPv6 outside AllowedIPs")
	}
	if guard.scope(netip.MustParseAddr("192.0.2.1")) != viaTunnel {
		t.Fatal("covered IPv4 must use the tunnel")
	}
}

func TestNameResolutionThroughTunnel(t *testing.T) {
	client := wgtest.NewKeyPair(t)
	s := wgtest.StartAWG(t, client, nil)
	wgtest.StartDNS(t, s, "echo.test.", wgtest.ServerV4)
	c := startClient(t, s.ClientText(client, "10.77.0.0/24"), ModeBlock, wgtest.ServerV4.String())
	echoTCP(t, c, "echo.test:7", 1024)
	if _, err := c.DialStream(context.Background(), "missing.test:7"); err == nil {
		t.Fatal("unknown name resolved")
	}
}

func TestCloseIsIdempotentAndStopsGoroutines(t *testing.T) {
	client := wgtest.NewKeyPair(t)
	s := wgtest.StartAWG(t, client, nil)
	before := runtime.NumGoroutine()
	for i := 0; i < 3; i++ {
		c := startClient(t, s.ClientText(client, "10.77.0.0/24"), "")
		pc, _ := c.ListenPacket(context.Background())
		echoUDP(t, c, netip.MustParseAddrPort("10.77.0.1:7"), 100)
		_ = c.Close()
		_ = c.Close()
		_ = pc.Close()
		if _, err := c.DialStream(context.Background(), "10.77.0.1:7"); !errors.Is(err, ErrClosed) {
			t.Fatalf("dial after close: %v", err)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > before+5 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > before+5 {
		t.Fatalf("goroutines leaked: %d before, %d after", before, n)
	}
}

func TestErrorsCarryNoSecrets(t *testing.T) {
	client := wgtest.NewKeyPair(t)
	s := wgtest.StartAWG(t, client, nil)
	c := startClient(t, s.ClientText(client, "10.77.0.0/24"), ModeBlock)
	for _, target := range []string{"192.0.2.1:1", "bad", "name.invalid:1"} {
		_, err := c.DialStream(context.Background(), target)
		if err == nil {
			continue
		}
		for _, secret := range []string{wgtest.B64(client.Private), wgtest.Hex(client.Private), wgtest.B64(s.PSK), wgtest.Hex(s.PSK), s.Addr.String()} {
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("error leaks a secret: %v", err)
			}
		}
	}
}

func TestDirectSocketHookPanicLeavesPacketClosable(t *testing.T) {
	client := &Client{}
	var setup context.Context
	client.outbound.ControlContext = func(ctx context.Context, _, _ string, _ syscall.RawConn) error {
		setup = ctx
		panic("socket hook")
	}
	packet := newScopedPacket(client)
	func() {
		defer func() {
			if got := recover(); got != "socket hook" {
				t.Fatalf("unexpected panic: %v", got)
			}
		}()
		_, _ = packet.directSocket(false)
	}()
	if setup.Err() != context.Canceled {
		t.Fatal("socket setup context still active after panic")
	}
	if !packet.mu.TryLock() {
		t.Fatal("packet lock held after hook panic")
	}
	packet.mu.Unlock()
	if err := packet.Close(); err != nil {
		t.Fatal(err)
	}
}
