package vpn

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xjasonlyu/tun2socks/v2/core"
	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/transport/shadowsocks"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"bimeron/internal/accesskey"
	"bimeron/internal/proxy"
	"bimeron/internal/routing"
	"bimeron/internal/telemetry"
)

func checksum(b []byte) uint16 {
	var sum uint32
	for len(b) > 1 {
		sum += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) > 0 {
		sum += uint32(b[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	return ^uint16(sum)
}
func ipPacket(dst net.IP, protocol byte, payload []byte) []byte {
	p := make([]byte, 20+len(payload))
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	p[8] = 64
	p[9] = protocol
	copy(p[12:16], net.IPv4(198, 18, 0, 1).To4())
	copy(p[16:20], dst.To4())
	binary.BigEndian.PutUint16(p[10:], checksum(p[:20]))
	copy(p[20:], payload)
	return p
}
func tcpPacket(dst net.IP, seq, ack uint32, flags byte, payload []byte) []byte {
	b := make([]byte, 20+len(payload))
	binary.BigEndian.PutUint16(b, 40000)
	binary.BigEndian.PutUint16(b[2:], 80)
	binary.BigEndian.PutUint32(b[4:], seq)
	binary.BigEndian.PutUint32(b[8:], ack)
	b[12] = 0x50
	b[13] = flags
	binary.BigEndian.PutUint16(b[14:], 65535)
	copy(b[20:], payload)
	pseudo := make([]byte, 12+len(b))
	copy(pseudo[:4], net.IPv4(198, 18, 0, 1).To4())
	copy(pseudo[4:8], dst.To4())
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:], uint16(len(b)))
	copy(pseudo[12:], b)
	binary.BigEndian.PutUint16(b[16:], checksum(pseudo))
	return ipPacket(dst, 6, b)
}
func testStack(t *testing.T, h *Handler) *channel.Endpoint {
	t.Helper()
	link := channel.New(64, 1420, "")
	s, err := core.CreateStack(&core.Config{LinkEndpoint: link, TransportHandler: h})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.Close(); s.Close(); link.Close() })
	return link
}
func inject(link *channel.Endpoint, p []byte) {
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(p)})
	defer pkt.DecRef()
	link.InjectInbound(header.IPv4ProtocolNumber, pkt)
}
func nextPacket(t *testing.T, ctx context.Context, link *channel.Endpoint) []byte {
	t.Helper()
	p := link.ReadContext(ctx)
	if p == nil {
		t.Fatal("timed out waiting for IP response")
	}
	defer p.DecRef()
	var b []byte
	for _, part := range p.AsSlices() {
		b = append(b, part...)
	}
	return b
}
func TestNetstackTCPOutline(t *testing.T) {
	keepOpen := make(chan struct{})
	defer close(keepOpen)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	key, _ := shadowsocks.NewEncryptionKey("aes-256-gcm", "test-only-secret")
	serverDone := make(chan error, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(4 * time.Second))
		r := shadowsocks.NewReader(c, key)
		w := shadowsocks.NewWriter(c, key)
		var request [11]byte
		_, err = io.ReadFull(r, request[:])
		if err == nil && (string(request[7:]) != "ping" || request[0] != 1 || request[1] != 203 || request[6] != 80) {
			err = io.ErrUnexpectedEOF
		}
		if err == nil {
			_, err = w.Write([]byte("pong"))
		}
		serverDone <- err
		<-keepOpen
	}()
	d, err := proxy.Outline(accesskey.Endpoint{Host: "127.0.0.1", Port: l.Addr().(*net.TCPAddr).Port, Cipher: "aes-256-gcm", Secret: "test-only-secret"})
	if err != nil {
		t.Fatal(err)
	}
	h := NewHandler(ctx)
	h.Stats = &telemetry.Counters{}
	h.TCP = d
	link := testStack(t, h)
	dst := net.IPv4(203, 0, 113, 10)
	inject(link, tcpPacket(dst, 100, 0, 2, nil))
	synack := nextPacket(t, ctx, link)
	offset := int(synack[0]&15) * 4
	if synack[offset+13]&0x12 != 0x12 {
		t.Fatalf("expected SYN ACK: %x", synack)
	}
	seq := binary.BigEndian.Uint32(synack[offset+4:])
	inject(link, tcpPacket(dst, 101, seq+1, 16, nil))
	inject(link, tcpPacket(dst, 101, seq+1, 24, []byte("ping")))
	for {
		p := nextPacket(t, ctx, link)
		i := int(p[0]&15) * 4
		tcpLen := int(p[i+12]>>4) * 4
		if string(p[i+tcpLen:]) == "pong" {
			break
		}
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		snapshot := h.Stats.Snapshot()
		if snapshot.BytesUp == 4 && snapshot.BytesDown == 4 && snapshot.TCPActive == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("open VPN stream statistics stale", snapshot)
		}
		time.Sleep(time.Millisecond)
	}
}
func TestNetstackUDPOutline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	l, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	key, _ := shadowsocks.NewEncryptionKey("aes-256-gcm", "test-only-secret")
	serverDone := make(chan error, 1)
	go func() {
		_ = l.SetReadDeadline(time.Now().Add(4 * time.Second))
		b := make([]byte, 16384)
		n, addr, err := l.ReadFrom(b)
		if err != nil {
			serverDone <- err
			return
		}
		plain, err := shadowsocks.Unpack(nil, b[:n], key)
		if err == nil && (len(plain) != 11 || string(plain[7:]) != "ping" || plain[1] != 203 || plain[4] != 10 || plain[6] != 53) {
			err = io.ErrUnexpectedEOF
		}
		if err == nil {
			reply := append(append([]byte{}, plain[:7]...), []byte("pong")...)
			encrypted, packErr := shadowsocks.Pack(make([]byte, 16384), reply, key)
			err = packErr
			if err == nil {
				_, err = l.WriteTo(encrypted, addr)
			}
		}
		serverDone <- err
	}()
	listener, err := proxy.OutlineUDP(accesskey.Endpoint{Host: "127.0.0.1", Port: l.LocalAddr().(*net.UDPAddr).Port, Cipher: "aes-256-gcm", Secret: "test-only-secret", Prefix: "GET "}, net.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	h := NewHandler(ctx)
	h.UDP = listener
	h.DNS = []string{"1.1.1.1"}
	h.Policy, _ = routing.Compile(routing.Config{Default: routing.Proxy})
	link := testStack(t, h)
	udp := make([]byte, 12)
	binary.BigEndian.PutUint16(udp, 40000)
	binary.BigEndian.PutUint16(udp[2:], 53)
	binary.BigEndian.PutUint16(udp[4:], 12)
	copy(udp[8:], "ping")
	inject(link, ipPacket(net.ParseIP("203.0.113.10"), 17, udp))
	response := nextPacket(t, ctx, link)
	if len(response) != 32 || string(response[28:]) != "pong" || !net.IP(response[12:16]).Equal(net.ParseIP("203.0.113.10")) || binary.BigEndian.Uint16(response[22:]) != 40000 {
		t.Fatalf("wrong DNS return packet: %x", response)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}
func TestDirectUDPNetstack(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	l, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		b := make([]byte, 1024)
		_ = l.SetReadDeadline(time.Now().Add(4 * time.Second))
		n, addr, err := l.ReadFrom(b)
		if err == nil {
			_, _ = l.WriteTo(b[:n], addr)
		}
	}()
	h := NewHandler(ctx)
	h.DirectUDP = transport.FuncPacketDialer(func(ctx context.Context, target string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", l.LocalAddr().String())
	})
	h.Policy, _ = routing.Compile(routing.Config{Default: routing.Direct})
	link := testStack(t, h)
	udp := make([]byte, 12)
	binary.BigEndian.PutUint16(udp, 40000)
	binary.BigEndian.PutUint16(udp[2:], uint16(l.LocalAddr().(*net.UDPAddr).Port))
	binary.BigEndian.PutUint16(udp[4:], 12)
	copy(udp[8:], "ping")
	inject(link, ipPacket(net.IPv4(203, 0, 113, 10), 17, udp))
	response := nextPacket(t, ctx, link)
	if string(response[28:]) != "ping" {
		t.Fatalf("wrong direct UDP packet: %x", response)
	}
}

func TestDisableIPv6Policy(t *testing.T) {
	h := NewHandler(context.Background())
	defer h.Close()
	h.DisableIPv6 = true
	h.Policy, _ = routing.Compile(routing.Config{Default: routing.Proxy, Rules: []routing.Rule{{CIDR: "::/0", Action: routing.Direct}}})
	for _, addr := range []string{"[2001:db8::1]:443", "[2001:db8::1]:53"} {
		_, action, err := h.target(addr)
		if err != nil || action != routing.Block {
			t.Fatal("IPv6 bypassed blocking", action, err)
		}
	}
	_, action, err := h.target("1.1.1.1:443")
	if err != nil || action != routing.Proxy {
		t.Fatal("IPv4 changed")
	}
	h.DisableIPv6 = false
	_, action, err = h.target("[2001:db8::1]:443")
	if err != nil || action != routing.Direct {
		t.Fatal("IPv6 enable changed")
	}
}
