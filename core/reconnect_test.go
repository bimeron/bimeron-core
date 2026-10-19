package core

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.getoutline.org/sdk/transport"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"bimeron/internal/routing"
	"bimeron/internal/vpn"
)

type persistentFake struct {
	fakeSession
	waits, retries, suspends atomic.Int32
}

func (s *persistentFake) Wait(ctx context.Context) error {
	if s.waits.Add(1) == 1 {
		return fault("network_changed", true)
	}
	<-ctx.Done()
	return ctx.Err()
}
func (s *persistentFake) Suspend() { s.suspends.Add(1) }
func (s *persistentFake) Reconnect(context.Context) error {
	if s.retries.Add(1) < 3 {
		return fault("transport_check_failed", true)
	}
	return nil
}
func TestPersistentRetryKeepsSession(t *testing.T) {
	var opens, closes atomic.Int32
	s := &persistentFake{fakeSession: fakeSession{close: func() error { closes.Add(1); return nil }}}
	e := testEngine(fakeBackend{open: func(context.Context) (session, error) { opens.Add(1); return s, nil }})
	ctx := testDeadline(t)
	if err := e.Start(ctx, testConfig()); err != nil {
		t.Fatal(err)
	}
	awaitState(t, e, Reconnecting)
	awaitState(t, e, Connected)
	if opens.Load() != 1 || closes.Load() != 0 || s.retries.Load() != 3 || s.suspends.Load() != 1 {
		t.Fatal("link recreated during transport retries")
	}
	if err := e.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if closes.Load() != 1 {
		t.Fatal("link not cleaned on Stop")
	}
}

type reconnectPlatform struct {
	path  networkPath
	opens int
}

func (p *reconnectPlatform) Acquire(context.Context) (func(), error) { return func() {}, nil }
func (p *reconnectPlatform) Inspect(context.Context, string, bool) (networkPath, error) {
	return p.path, nil
}
func (p *reconnectPlatform) Open(context.Context, SessionConfig, *flowRouter, func(string, string)) (link, error) {
	p.opens++
	return nil, errors.New("must not recreate link")
}
func TestVPNReconnectChangesGenerationOnly(t *testing.T) {
	ctx := testDeadline(t)
	refreshes := 0
	p := &reconnectPlatform{path: networkPath{identity: "wifi", refresh: func(context.Context) error {
		refreshes++
		return nil
	}}}
	c := testConfig()
	r := &flowRouter{}
	r.replace(vpn.NewHandler(ctx))
	defer r.Close()
	attempts := 0
	metadata := vpn.NewDNSMetadata()
	s := &vpnSession{ctx: ctx, cfg: c, path: networkPath{identity: "ethernet"}, router: r, platform: p, report: func(string, string) {}, metadata: metadata,
		prepare: func(lifetime, attempt context.Context, _ SessionConfig, _ networkPath, _ func(string, string), got *vpn.DNSMetadata) (*vpn.Handler, transport.StreamDialer, transport.PacketListener, error) {
			if got != metadata {
				t.Fatal("DNS metadata replaced during reconnect")
			}
			attempts++
			if attempts == 1 {
				return nil, nil, nil, fault("transport_check_failed", true)
			}
			h := vpn.NewHandler(lifetime)
			h.Metadata = got
			return h, nil, nil, nil
		}}
	s.Suspend()
	if err := s.Reconnect(ctx); !retryable(err) {
		t.Fatal(err)
	}
	if r.current == nil || r.current.TCP != nil || r.current.UDP != nil {
		t.Fatal("proxy transport remained live while offline")
	}
	if err := s.Reconnect(ctx); err != nil {
		t.Fatal(err)
	}
	if p.opens != 0 || s.path.identity != "wifi" || refreshes != 1 {
		t.Fatal("adapter recreated or stale network path")
	}
	if r.current.Metadata != metadata {
		t.Fatal("DNS metadata did not survive reconnect")
	}
}

func TestVPNMetadataIsScopedToSession(t *testing.T) {
	first := newBackend(DefaultConfig()).(*vpnBackend)
	second := newBackend(DefaultConfig()).(*vpnBackend)
	if first.metadata == nil || second.metadata == nil || first.metadata == second.metadata {
		t.Fatal("VPN sessions share DNS metadata")
	}
}

type testFlow struct {
	net.Conn
	destination string
}

func (c testFlow) LocalAddr() net.Addr          { a, _ := net.ResolveTCPAddr("tcp", c.destination); return a }
func (testFlow) ID() *stack.TransportEndpointID { return nil }
func (c testFlow) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := c.Read(b)
	return n, c.RemoteAddr(), err
}
func (c testFlow) WriteTo(b []byte, _ net.Addr) (int, error) { return c.Write(b) }

type failStreamDialer struct{ calls *atomic.Int32 }

func (d failStreamDialer) DialStream(context.Context, string) (transport.StreamConn, error) {
	d.calls.Add(1)
	return nil, errors.New("test error")
}

type failPacketDialer struct{ calls *atomic.Int32 }

func (d failPacketDialer) DialPacket(context.Context, string) (net.Conn, error) {
	d.calls.Add(1)
	return nil, errors.New("test error")
}

func TestOfflineProxyNeverUsesDirect(t *testing.T) {
	ctx := testDeadline(t)
	h := vpn.NewHandler(ctx)
	r := &flowRouter{}
	r.replace(h)
	defer r.Close()
	var tcpCalls, udpCalls atomic.Int32
	h.DirectTCP = failStreamDialer{&tcpCalls}
	h.DirectUDP = failPacketDialer{&udpCalls}
	h.Policy, _ = routing.Compile(routing.Config{Default: routing.Proxy, Rules: []routing.Rule{{CIDR: "192.0.2.1/32", Action: routing.Direct}}})
	for _, udp := range []bool{false, true} {
		for _, destination := range []string{"203.0.113.1:443", "192.0.2.1:443"} {
			local, client := net.Pipe()
			_ = client.SetReadDeadline(time.Now().Add(time.Second))
			flow := testFlow{Conn: local, destination: destination}
			if udp {
				r.HandleUDP(flow)
			} else {
				r.HandleTCP(flow)
			}
			if _, err := client.Read(make([]byte, 1)); err != io.EOF {
				t.Fatalf("offline flow not closed: %v", err)
			}
			_ = client.Close()
		}
	}
	if tcpCalls.Load() != 1 || udpCalls.Load() != 1 {
		t.Fatal("proxy traffic leaked into direct transport", tcpCalls.Load(), udpCalls.Load())
	}
}

func TestBootstrapDNSUsesBoundInterface(t *testing.T) {
	for _, physicalDNS := range [][]string{{"192.0.2.53"}, nil} {
		var destination string
		p := networkPath{dns: physicalDNS, dialer: net.Dialer{Control: func(network, address string, _ syscall.RawConn) error {
			destination = address
			return errors.New("captured; no network sent")
		}}}
		d := bootstrapDialer(p, []string{"198.51.100.53"})
		_, err := d.Resolver.Dial(context.Background(), "udp", "198.18.0.2:53")
		if err == nil {
			t.Fatal("expected test cancellation")
		}
		want := "192.0.2.53:53"
		if physicalDNS == nil {
			want = "198.51.100.53:53"
		}
		if destination != want {
			t.Fatalf("DNS used tunnel/default path: %s", destination)
		}
	}
}
