// Package wgtest runs in-process WireGuard and AmneziaWG reference servers on
// 127.0.0.1 for tests and benchmarks. Keys are generated per run.
package wgtest

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"

	awgconn "github.com/amnezia-vpn/amneziawg-go/v3/conn"
	awgdevice "github.com/amnezia-vpn/amneziawg-go/v3/device"
	awgnetstack "github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/net/dns/dnsmessage"
	upconn "golang.zx2c4.com/wireguard/conn"
	updevice "golang.zx2c4.com/wireguard/device"
	upnetstack "golang.zx2c4.com/wireguard/tun/netstack"
)

// KeyPair is a freshly generated test key pair; never a real key.
type KeyPair struct{ Private, Public [32]byte }

func NewKeyPair(t testing.TB) KeyPair {
	t.Helper()
	var k KeyPair
	if _, err := rand.Read(k.Private[:]); err != nil {
		t.Fatal(err)
	}
	k.Private[0] &= 248
	k.Private[31] = (k.Private[31] & 127) | 64
	pub, err := curve25519.X25519(k.Private[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	copy(k.Public[:], pub)
	return k
}

func B64(k [32]byte) string { return base64.StdEncoding.EncodeToString(k[:]) }
func Hex(k [32]byte) string { return hex.EncodeToString(k[:]) }

// Tunnel addressing shared by the reference servers and clients.
var (
	ServerV4 = netip.MustParseAddr("10.77.0.1")
	ClientV4 = netip.MustParseAddr("10.77.0.2")
	ServerV6 = netip.MustParseAddr("fd77::1")
	ClientV6 = netip.MustParseAddr("fd77::2")
)

// Server is a reference WireGuard server on 127.0.0.1 with TCP and UDP
// echo services inside its tunnel.
type Server struct {
	Addr   netip.AddrPort
	Key    KeyPair
	PSK    [32]byte
	close  func()
	listen func(network string, at netip.AddrPort) (any, error)
}

// StartAWG runs amneziawg-go; awg lines are its device options in configuration
// protocol form, such as "jc=4".
func StartAWG(t testing.TB, client KeyPair, awg []string) *Server {
	t.Helper()
	s := &Server{Key: NewKeyPair(t)}
	_, _ = rand.Read(s.PSK[:])
	tun, tnet, err := awgnetstack.CreateNetTUN([]netip.Addr{ServerV4, ServerV6}, nil, 1420)
	if err != nil {
		t.Fatal(err)
	}
	bind := &awgLoopBind{}
	dev := awgdevice.NewDevice(tun, bind, awgdevice.NewLogger(awgdevice.LogLevelSilent, ""))
	uapi := fmt.Sprintf("private_key=%s\nlisten_port=0\n%speer_public_key_placeholder\n", Hex(s.Key.Private), JoinLines(awg))
	uapi = strings.Replace(uapi, "peer_public_key_placeholder\n", fmt.Sprintf("public_key=%s\npreshared_key=%s\nallowed_ip=%s/32\nallowed_ip=%s/128\n", Hex(client.Public), Hex(s.PSK), ClientV4, ClientV6), 1)
	if err := dev.IpcSet(uapi); err != nil {
		t.Fatalf("server config: %v", err)
	}
	if err := dev.Up(); err != nil {
		t.Fatal(err)
	}
	s.Addr = bind.addr()
	s.close = dev.Close
	s.listen = func(network string, at netip.AddrPort) (any, error) {
		if network == "tcp" {
			return tnet.ListenTCPAddrPort(at)
		}
		return tnet.ListenUDPAddrPort(at)
	}
	s.serveEcho(t)
	t.Cleanup(s.close)
	return s
}

// StartUpstream runs upstream wireguard-go, the plain WireGuard
// reference implementation.
func StartUpstream(t testing.TB, client KeyPair) *Server {
	t.Helper()
	s := &Server{Key: NewKeyPair(t)}
	_, _ = rand.Read(s.PSK[:])
	tun, tnet, err := upnetstack.CreateNetTUN([]netip.Addr{ServerV4, ServerV6}, nil, 1420)
	if err != nil {
		t.Fatal(err)
	}
	bind := &upLoopBind{}
	dev := updevice.NewDevice(tun, bind, updevice.NewLogger(updevice.LogLevelSilent, ""))
	uapi := fmt.Sprintf("private_key=%s\nlisten_port=0\npublic_key=%s\npreshared_key=%s\nallowed_ip=%s/32\nallowed_ip=%s/128\n", Hex(s.Key.Private), Hex(client.Public), Hex(s.PSK), ClientV4, ClientV6)
	if err := dev.IpcSet(uapi); err != nil {
		t.Fatalf("server config: %v", err)
	}
	if err := dev.Up(); err != nil {
		t.Fatal(err)
	}
	s.Addr = bind.addr()
	s.close = dev.Close
	s.listen = func(network string, at netip.AddrPort) (any, error) {
		if network == "tcp" {
			return tnet.ListenTCPAddrPort(at)
		}
		return tnet.ListenUDPAddrPort(at)
	}
	s.serveEcho(t)
	t.Cleanup(s.close)
	return s
}

func JoinLines(lines []string) string {
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n") + "\n"
}

// serveEcho runs TCP and UDP echo on port 7 of both tunnel addresses.
func (s *Server) serveEcho(t testing.TB) {
	for _, ip := range []netip.Addr{ServerV4, ServerV6} {
		l, err := s.listen("tcp", netip.AddrPortFrom(ip, 7))
		if err != nil {
			t.Fatal(err)
		}
		listener := l.(net.Listener)
		go func() {
			for {
				c, err := listener.Accept()
				if err != nil {
					return
				}
				go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
			}
		}()
		u, err := s.listen("udp", netip.AddrPortFrom(ip, 7))
		if err != nil {
			t.Fatal(err)
		}
		pc := u.(net.PacketConn)
		go func() {
			buf := make([]byte, 65535)
			for {
				n, from, err := pc.ReadFrom(buf)
				if err != nil {
					return
				}
				_, _ = pc.WriteTo(buf[:n], from)
			}
		}()
		t.Cleanup(func() { _ = listener.Close(); _ = pc.Close() })
	}
}

// loopSocket is a 127.0.0.1 UDP socket serving any peer, for test servers.
type loopSocket struct {
	mu   sync.Mutex
	sock *net.UDPConn
}

func (l *loopSocket) open() (*net.UDPConn, uint16, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	s, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, 0, err
	}
	l.sock = s
	return s, uint16(s.LocalAddr().(*net.UDPAddr).Port), nil
}

func (l *loopSocket) addr() netip.AddrPort {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.sock.LocalAddr().(*net.UDPAddr).AddrPort()
}

func (l *loopSocket) close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.sock == nil {
		return nil
	}
	err := l.sock.Close()
	l.sock = nil
	return err
}

func (l *loopSocket) send(bufs [][]byte, to netip.AddrPort) error {
	l.mu.Lock()
	s := l.sock
	l.mu.Unlock()
	if s == nil {
		return net.ErrClosed
	}
	for _, b := range bufs {
		if _, err := s.WriteToUDPAddrPort(b, to); err != nil {
			return err
		}
	}
	return nil
}

type awgLoopBind struct{ loopSocket }

func (b *awgLoopBind) Open(uint16) ([]awgconn.ReceiveFunc, uint16, error) {
	s, port, err := b.open()
	if err != nil {
		return nil, 0, err
	}
	return []awgconn.ReceiveFunc{func(p [][]byte, sizes []int, eps []awgconn.Endpoint) (int, error) {
		n, from, err := s.ReadFromUDPAddrPort(p[0])
		if err != nil {
			return 0, net.ErrClosed
		}
		sizes[0], eps[0] = n, awgEndpoint(from)
		return 1, nil
	}}, port, nil
}
func (b *awgLoopBind) Close() error         { return b.close() }
func (b *awgLoopBind) SetMark(uint32) error { return nil }
func (b *awgLoopBind) BatchSize() int       { return 1 }
func (b *awgLoopBind) Send(bufs [][]byte, ep awgconn.Endpoint) error {
	return b.send(bufs, netip.AddrPort(ep.(awgEndpoint)))
}
func (b *awgLoopBind) ParseEndpoint(s string) (awgconn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	return awgEndpoint(ap), err
}

type upEndpoint netip.AddrPort

func (e upEndpoint) ClearSrc()           {}
func (e upEndpoint) SrcToString() string { return "" }
func (e upEndpoint) DstToString() string { return netip.AddrPort(e).String() }
func (e upEndpoint) DstToBytes() []byte  { b, _ := netip.AddrPort(e).MarshalBinary(); return b }
func (e upEndpoint) DstIP() netip.Addr   { return netip.AddrPort(e).Addr() }
func (e upEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }

type upLoopBind struct{ loopSocket }

func (b *upLoopBind) Open(uint16) ([]upconn.ReceiveFunc, uint16, error) {
	s, port, err := b.open()
	if err != nil {
		return nil, 0, err
	}
	return []upconn.ReceiveFunc{func(p [][]byte, sizes []int, eps []upconn.Endpoint) (int, error) {
		n, from, err := s.ReadFromUDPAddrPort(p[0])
		if err != nil {
			return 0, net.ErrClosed
		}
		sizes[0], eps[0] = n, upEndpoint(from)
		return 1, nil
	}}, port, nil
}
func (b *upLoopBind) Close() error         { return b.close() }
func (b *upLoopBind) SetMark(uint32) error { return nil }
func (b *upLoopBind) BatchSize() int       { return 1 }
func (b *upLoopBind) Send(bufs [][]byte, ep upconn.Endpoint) error {
	return b.send(bufs, netip.AddrPort(ep.(upEndpoint)))
}
func (b *upLoopBind) ParseEndpoint(s string) (upconn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	return upEndpoint(ap), err
}

// StartDNS answers A queries for name with ip on the server's tunnel
// address, port 53 over UDP. Other names get NXDOMAIN.
func StartDNS(t testing.TB, s *Server, name string, ip netip.Addr) {
	t.Helper()
	u, err := s.listen("udp", netip.AddrPortFrom(ServerV4, 53))
	if err != nil {
		t.Fatal(err)
	}
	pc := u.(net.PacketConn)
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var m dnsmessage.Message
			if m.Unpack(buf[:n]) != nil || len(m.Questions) != 1 {
				continue
			}
			q := m.Questions[0]
			m.Response, m.RecursionAvailable = true, true
			if q.Name.String() == name && q.Type == dnsmessage.TypeA {
				m.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: ip.As4()}}}
			} else if q.Name.String() != name {
				m.RCode = dnsmessage.RCodeNameError
			}
			out, err := m.Pack()
			if err == nil {
				_, _ = pc.WriteTo(out, from)
			}
		}
	}()
}

type awgEndpoint netip.AddrPort

func (e awgEndpoint) ClearSrc()           {}
func (e awgEndpoint) SrcToString() string { return "" }
func (e awgEndpoint) DstToString() string { return netip.AddrPort(e).String() }
func (e awgEndpoint) DstToBytes() []byte  { b, _ := netip.AddrPort(e).MarshalBinary(); return b }
func (e awgEndpoint) DstIP() netip.Addr   { return netip.AddrPort(e).Addr() }
func (e awgEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }

// ClientText builds wg-quick text for a client of s. awg lines are
// AmneziaWG [Interface] options in text form.
func (s *Server) ClientText(client KeyPair, allowed string, awg ...string) string {
	return "[Interface]\nPrivateKey = " + B64(client.Private) + "\nAddress = " + ClientV4.String() + "/32, " + ClientV6.String() + "/128\n" +
		JoinLines(awg) +
		"[Peer]\nPublicKey = " + B64(s.Key.Public) + "\nPresharedKey = " + B64(s.PSK) + "\nEndpoint = " + s.Addr.String() + "\nAllowedIPs = " + allowed + "\n"
}

// Profile pairs matching server device options and client text options.
type Profile struct{ Server, Client []string }

// Profiles covers each AmneziaWG version family.
var Profiles = map[string]Profile{
	"awg-1.0": {
		Server: []string{"jc=4", "jmin=40", "jmax=70", "s1=50", "s2=100", "h1=1234", "h2=5678", "h3=9012", "h4=3456"},
		Client: []string{"Jc = 4", "Jmin = 40", "Jmax = 70", "S1 = 50", "S2 = 100", "H1 = 1234", "H2 = 5678", "H3 = 9012", "H4 = 3456"},
	},
	"awg-1.5": {
		Server: []string{"s1=50", "s2=100", "h1=1234", "h2=5678", "h3=9012", "h4=3456"},
		Client: []string{"Jc = 3", "Jmin = 10", "Jmax = 30", "S1 = 50", "S2 = 100", "H1 = 1234", "H2 = 5678", "H3 = 9012", "H4 = 3456", "I1 = <r 2><b 0x858000010001000000000000><rc 8><t>", "I2 = <rd 16>"},
	},
	"awg-2.0": {
		Server: []string{"s1=40", "s2=60", "s3=20", "s4=16", "h1=100000-199999", "h2=200000-299999", "h3=300000-399999", "h4=400000-499999"},
		Client: []string{"Jc = 5", "Jmin = 20", "Jmax = 90", "S1 = 40", "S2 = 60", "S3 = 20", "S4 = 16", "H1 = 100000-199999", "H2 = 200000-299999", "H3 = 300000-399999", "H4 = 400000-499999"},
	},
}

func init() {
	var hp [32]byte
	_, _ = rand.Read(hp[:])
	Profiles["awg-3.1"] = Profile{
		Server: []string{"s1=24", "s2=24", "s3=24", "s4=24", "h1=100-199", "h2=200-299", "h3=300-399", "h4=400-499", "header_protection_key=" + Hex(hp), "random_trailers=true", "disable_cookies=true"},
		Client: []string{"Jc = 4", "Jmin = 30", "Jmax = 60", "S1 = 24", "S2 = 24", "S3 = 24", "S4 = 24", "H1 = 100-199", "H2 = 200-299", "H3 = 300-399", "H4 = 400-499", "HeaderProtectionKey = " + B64(hp), "RandomTrailers = true", "DisableCookies = true", "ContentPaddingAddition = 0-32", "RekeyAfterTime = 100-130", "MaxHandshakeAttempts = 15-20"},
	}
}
