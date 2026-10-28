package core

import (
	"context"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"bimeron/internal/accesskey"
	"bimeron/internal/masque"
	"bimeron/internal/masque/masquetest"
	"bimeron/internal/proxy"
	"bimeron/internal/telemetry"
	"bimeron/internal/vpn"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func TestMASQUEProxyBackend(t *testing.T) {
	endpoints := masquetest.Start(t)
	p := masquetest.Profile(t, endpoints)
	cfg := DefaultConfig()
	cfg.Mode, cfg.Listen = "proxy", "127.0.0.1:0"
	cfg.stats = &telemetry.Counters{}
	cfg.Resolve = func(context.Context) (Profile, error) { return p, nil }
	var accepted sessionEndpoints
	cfg.endpointChanged = func(e sessionEndpoints) { accepted = e }
	session, err := (proxyBackend{}).Open(t.Context(), cfg, func(string, string) {})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if accepted.tcp != endpoints["server"] || accepted.udp != accepted.tcp {
		t.Fatalf("endpoint status: %+v", accepted)
	}
	host, portText, _ := net.SplitHostPort(session.(*proxySession).listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	socks := &proxy.SOCKS5{Endpoint: accesskey.Endpoint{Host: host, Port: port}, Dialer: net.Dialer{Timeout: time.Second}}
	tcp, err := socks.DialStream(t.Context(), endpoints["tcp"])
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	_ = tcp.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := tcp.Write([]byte("tcp-via-socks")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 13)
	if _, err := io.ReadFull(tcp, got); err != nil || string(got) != "tcp-via-socks" {
		t.Fatalf("TCP relay: %q %v", got, err)
	}
	packet, err := socks.ListenPacket(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	_ = packet.SetDeadline(time.Now().Add(5 * time.Second))
	for _, target := range []string{endpoints["udp"], endpoints["udp2"]} {
		destination, err := net.ResolveUDPAddr("udp", target)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := packet.WriteTo([]byte("udp-via-socks"), destination); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 64)
		n, from, err := packet.ReadFrom(b)
		if err != nil || from.String() != target || string(b[:n]) != "udp-via-socks" {
			t.Fatalf("UDP relay: %q %v %v", b[:n], from, err)
		}
	}
	// Engine shutdown must terminate active UDP associations as well as TCP relays.
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestResolveMASQUEOnVPNPathPreservesAuthorityAndUDP(t *testing.T) {
	for _, endpoint := range []string{"127.0.0.1:443", "[::1]:443"} {
		cfg := DefaultConfig()
		cfg.Resolve = func(context.Context) (Profile, error) {
			return accesskey.ParseMASQUE("masque://" + endpoint + "?sni=tls.example")
		}
		p, _, endpoints, err := resolveOnPath(t.Context(), cfg, networkPath{dialer: net.Dialer{}})
		if err != nil {
			t.Fatal(err)
		}
		host, _, _ := net.SplitHostPort(endpoint)
		if p.MASQUE.ServerName != "tls.example" || p.MASQUE.ProxyHost != host || p.UDP != p.TCP || endpoints.tcp != endpoint || endpoints.udp != endpoint {
			t.Fatalf("VPN endpoints: %+v %+v", p.MASQUE, endpoints)
		}
	}
}

// Exercise the real VPN flow handler against the reference proxy without
// installing system routes or requiring an administrator-owned TUN adapter.
func TestMASQUEVPNFlows(t *testing.T) {
	endpoints := masquetest.Start(t)
	client, err := masque.New(masquetest.Profile(t, endpoints), net.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	h := directHandler(t.Context(), DefaultConfig(), networkPath{}, func(string, string) {}, vpn.NewDNSMetadata())
	h.TCP, h.UDP = client, client
	defer h.Close()
	tcpTarget, err := net.ResolveTCPAddr("tcp", endpoints["tcp"])
	if err != nil {
		t.Fatal(err)
	}
	local, flow := net.Pipe()
	defer local.Close()
	h.HandleTCP(&masqueTCPFlow{Conn: flow, target: tcpTarget})
	_ = local.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := local.Write([]byte("vpn-tcp")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 7)
	if _, err := io.ReadFull(local, b); err != nil || string(b) != "vpn-tcp" {
		t.Fatal(err)
	}
	source, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	socket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	target, err := net.ResolveUDPAddr("udp", endpoints["udp"])
	if err != nil {
		t.Fatal(err)
	}
	h.HandleUDP(&masqueUDPFlow{PacketConn: socket, peer: source.LocalAddr(), target: target})
	_ = source.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := source.WriteTo([]byte("vpn-udp"), socket.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	if n, _, err := source.ReadFrom(b); err != nil || string(b[:n]) != "vpn-udp" {
		t.Fatal(err)
	}
}

type masqueTCPFlow struct {
	net.Conn
	target net.Addr
}

func (c *masqueTCPFlow) LocalAddr() net.Addr            { return c.target }
func (c *masqueTCPFlow) ID() *stack.TransportEndpointID { return nil }

type masqueUDPFlow struct {
	net.PacketConn
	peer, target net.Addr
}

func (c *masqueUDPFlow) LocalAddr() net.Addr            { return c.target }
func (c *masqueUDPFlow) RemoteAddr() net.Addr           { return c.peer }
func (c *masqueUDPFlow) ID() *stack.TransportEndpointID { return nil }
func (c *masqueUDPFlow) Read(b []byte) (int, error)     { n, _, err := c.ReadFrom(b); return n, err }
func (c *masqueUDPFlow) Write(b []byte) (int, error)    { return c.PacketConn.WriteTo(b, c.peer) }
