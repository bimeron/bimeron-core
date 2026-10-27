package vpn

import (
	"bimeron/internal/routing"
	"bimeron/internal/telemetry"
	"context"
	"encoding/binary"
	"fmt"
	"golang.getoutline.org/sdk/transport"
	"golang.org/x/net/dns/dnsmessage"
	"io"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type packetListenerFunc func(context.Context) (net.PacketConn, error)

type diagnosticHTTPError struct{}

func (diagnosticHTTPError) Error() string       { return "private upstream request metadata" }
func (diagnosticHTTPError) HTTPStatusCode() int { return 502 }

func TestDNSDiagnosticHTTPStatusRedactsMetadata(t *testing.T) {
	err := dnsAttemptError{"TCP read", fmt.Errorf("private wrapper: %w", diagnosticHTTPError{})}
	if got := dnsAttemptDetail(err); got != "TCP read upstream HTTP 502" {
		t.Fatalf("diagnostic: %q", got)
	}
}

func (f packetListenerFunc) ListenPacket(ctx context.Context) (net.PacketConn, error) { return f(ctx) }

type routedDNSPacket struct {
	net.PacketConn
	routes map[string]string
	source net.Addr
	record func(string)
}

type dnsTCPFlow struct{ net.Conn }

func (dnsTCPFlow) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP(DNSAddress), Port: 53}
}
func (dnsTCPFlow) ID() *stack.TransportEndpointID { return nil }

func (c *routedDNSPacket) WriteTo(b []byte, addr net.Addr) (int, error) {
	c.source = addr
	c.record(addr.String())
	actual, ok := c.routes[addr.String()]
	if !ok {
		return len(b), nil
	}
	a, err := net.ResolveUDPAddr("udp", actual)
	if err != nil {
		return 0, err
	}
	return c.PacketConn.WriteTo(b, a)
}
func (c *routedDNSPacket) ReadFrom(b []byte) (int, net.Addr, error) {
	n, _, err := c.PacketConn.ReadFrom(b)
	return n, c.source, err
}
func dnsQuery(t *testing.T) []byte {
	t.Helper()
	name, _ := dnsmessage.NewName("example.org.")
	b, err := (&dnsmessage.Message{Header: dnsmessage.Header{ID: 1234, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}).Pack()
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func dnsAnswer(query []byte, rcode dnsmessage.RCode) []byte {
	var q dnsmessage.Message
	if q.Unpack(query) != nil {
		return nil
	}
	response := dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true, RecursionAvailable: true, RCode: rcode}, Questions: q.Questions}
	if rcode == dnsmessage.RCodeSuccess {
		response.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: [4]byte{1, 2, 3, 4}}}}
	}
	b, _ := response.Pack()
	return b
}
func udpDNSFixture(t *testing.T, rcode dnsmessage.RCode) string {
	t.Helper()
	l, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		buffer := make([]byte, 4096)
		for {
			n, addr, err := l.ReadFrom(buffer)
			if err != nil {
				return
			}
			_, _ = l.WriteTo(dnsAnswer(buffer[:n], rcode), addr)
		}
	}()
	return l.LocalAddr().String()
}
func TestDNSPriorityAndFallback(t *testing.T) {
	for _, tc := range []struct {
		name      string
		first     dnsmessage.RCode
		drop      bool
		wantCalls int
		wantCode  dnsmessage.RCode
	}{
		{"primary", dnsmessage.RCodeSuccess, false, 1, dnsmessage.RCodeSuccess},
		{"servfail", dnsmessage.RCodeServerFailure, false, 2, dnsmessage.RCodeSuccess},
		{"refused", dnsmessage.RCodeRefused, false, 2, dnsmessage.RCodeSuccess},
		{"timeout", dnsmessage.RCodeSuccess, true, 2, dnsmessage.RCodeSuccess},
		{"nxdomain", dnsmessage.RCodeNameError, false, 1, dnsmessage.RCodeNameError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			routes := map[string]string{"203.0.113.2:53": udpDNSFixture(t, dnsmessage.RCodeSuccess)}
			if !tc.drop {
				routes["203.0.113.1:53"] = udpDNSFixture(t, tc.first)
			}
			var calls []string
			listener := packetListenerFunc(func(context.Context) (net.PacketConn, error) {
				c, err := net.ListenPacket("udp", "127.0.0.1:0")
				return &routedDNSPacket{PacketConn: c, routes: routes, record: func(s string) { calls = append(calls, s) }}, err
			})
			resolver := DNSResolver{Servers: []string{"203.0.113.1", "203.0.113.2"}, UDP: listener, Timeout: 50 * time.Millisecond}
			b, err := resolver.Exchange(context.Background(), dnsQuery(t), false)
			if err != nil {
				t.Fatal(err)
			}
			var answer dnsmessage.Message
			if err := answer.Unpack(b); err != nil || answer.RCode != tc.wantCode {
				t.Fatalf("answer: %v", err)
			}
			expected := []string{"203.0.113.1:53"}
			if tc.wantCalls == 2 {
				expected = append(expected, "203.0.113.2:53")
			}
			if !reflect.DeepEqual(calls, expected) {
				t.Fatalf("resolver order: %v", calls)
			}
		})
	}
}

func TestDNSFailureReportsSafeAttemptStages(t *testing.T) {
	secret := "vless://private-profile"
	listener := packetListenerFunc(func(context.Context) (net.PacketConn, error) {
		return nil, fmt.Errorf("UDP open failed for %s", secret)
	})
	resolver := DNSResolver{Servers: []string{"203.0.113.1", "203.0.113.2"}, UDP: listener}
	_, err := resolver.Exchange(t.Context(), dnsQuery(t), false)
	if err == nil || !strings.Contains(err.Error(), "resolver 1: UDP open failed") || !strings.Contains(err.Error(), "resolver 2: UDP open failed") || strings.Contains(err.Error(), secret) {
		t.Fatalf("unsafe or incomplete DNS diagnostic: %v", err)
	}
}

func TestDNSFailureReportsTimeout(t *testing.T) {
	listener := packetListenerFunc(func(context.Context) (net.PacketConn, error) {
		c, err := net.ListenPacket("udp", "127.0.0.1:0")
		return &routedDNSPacket{PacketConn: c, routes: map[string]string{}, record: func(string) {}}, err
	})
	resolver := DNSResolver{Servers: []string{"203.0.113.1"}, UDP: listener, Timeout: 20 * time.Millisecond}
	_, err := resolver.Exchange(t.Context(), dnsQuery(t), false)
	if err == nil || !strings.Contains(err.Error(), "resolver 1: UDP read timeout") {
		t.Fatalf("missing DNS timeout stage: %v", err)
	}
}

func TestDNSReadFailureCategories(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{dnsAttemptError{"UDP read", io.EOF}, "UDP read end of stream"},
		{dnsAttemptError{"UDP read", io.ErrUnexpectedEOF}, "UDP read truncated stream"},
		{dnsAttemptError{"UDP read", fmt.Errorf("private endpoint: %s", "vless://secret")}, "UDP read failed"},
	} {
		if got := dnsAttemptDetail(tc.err); got != tc.want {
			t.Fatalf("got %q, want %q", got, tc.want)
		}
	}
}
func tcpDNSFixture(t *testing.T, rcode dnsmessage.RCode) string {
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
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(time.Second))
				var length [2]byte
				if _, err := io.ReadFull(c, length[:]); err != nil {
					return
				}
				query := make([]byte, int(binary.BigEndian.Uint16(length[:])))
				if _, err := io.ReadFull(c, query); err != nil {
					return
				}
				response := dnsAnswer(query, rcode)
				frame := make([]byte, 2+len(response))
				binary.BigEndian.PutUint16(frame, uint16(len(response)))
				copy(frame[2:], response)
				_, _ = c.Write(frame)
			}()
		}
	}()
	return l.Addr().String()
}
func TestDNSTCPFallbackAndCancellation(t *testing.T) {
	routes := map[string]string{"203.0.113.1:53": tcpDNSFixture(t, dnsmessage.RCodeRefused), "203.0.113.2:53": tcpDNSFixture(t, dnsmessage.RCodeSuccess)}
	var calls []string
	dialer := transport.FuncStreamDialer(func(ctx context.Context, address string) (transport.StreamConn, error) {
		calls = append(calls, address)
		return (&transport.TCPDialer{}).DialStream(ctx, routes[address])
	})
	resolver := DNSResolver{Servers: []string{"203.0.113.1", "203.0.113.2"}, TCP: dialer, Timeout: time.Second}
	query := dnsQuery(t)
	b, err := resolver.Exchange(context.Background(), query, true)
	if err != nil {
		t.Fatal(err)
	}
	var answer dnsmessage.Message
	if answer.Unpack(b) != nil || len(answer.Answers) != 1 {
		t.Fatal("invalid TCP answer")
	}
	if len(calls) != 2 {
		t.Fatal("TCP did not retry")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := resolver.Exchange(ctx, query, true); err == nil {
		t.Fatal("ignored cancellation")
	}
	if len(calls) != 2 {
		t.Fatal("cancelled query dialed a resolver")
	}
}

func TestNetstackDNSTCPMetadata(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	upstream := tcpDNSFixture(t, dnsmessage.RCodeSuccess)
	h := NewHandler(ctx)
	defer h.Close()
	h.Stats = &telemetry.Counters{}
	h.DNS = []string{"203.0.113.1"}
	h.Policy, _ = routing.Compile(routing.Config{Default: routing.Direct, Rules: []routing.Rule{{Domain: "example.org", Action: routing.Proxy}}})
	h.TCP = transport.FuncStreamDialer(func(ctx context.Context, _ string) (transport.StreamConn, error) {
		return (&transport.TCPDialer{}).DialStream(ctx, upstream)
	})
	client, server := net.Pipe()
	defer client.Close()
	h.handleDNSTCP(dnsTCPFlow{server})
	query := dnsQuery(t)
	frame := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(frame, uint16(len(query)))
	copy(frame[2:], query)
	if _, err := client.Write(frame); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	var size [2]byte
	if _, err := io.ReadFull(client, size[:]); err != nil {
		t.Fatal(err)
	}
	answer := make([]byte, int(binary.BigEndian.Uint16(size[:])))
	if _, err := io.ReadFull(client, answer); err != nil {
		t.Fatal(err)
	}
	if _, action, err := h.target("1.2.3.4:443"); err != nil || action != routing.Proxy {
		t.Fatal("TCP DNS metadata was not applied", action, err)
	}
}
func TestNetstackDNSFailoverAndTranslation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	routes := map[string]string{"203.0.113.1:53": udpDNSFixture(t, dnsmessage.RCodeServerFailure), "203.0.113.2:53": udpDNSFixture(t, dnsmessage.RCodeSuccess)}
	var mu sync.Mutex
	var calls []string
	listener := packetListenerFunc(func(context.Context) (net.PacketConn, error) {
		c, err := net.ListenPacket("udp", "127.0.0.1:0")
		return &routedDNSPacket{PacketConn: c, routes: routes, record: func(s string) { mu.Lock(); calls = append(calls, s); mu.Unlock() }}, err
	})
	h := NewHandler(ctx)
	h.DNS = []string{"203.0.113.1", "203.0.113.2"}
	h.UDP = listener
	h.Policy, _ = routing.Compile(routing.Config{Default: routing.Direct, Rules: []routing.Rule{{Domain: "example.org", Action: routing.Proxy}}})
	link := testStack(t, h)
	query := dnsQuery(t)
	udp := make([]byte, 8+len(query))
	binary.BigEndian.PutUint16(udp, 40000)
	binary.BigEndian.PutUint16(udp[2:], 53)
	binary.BigEndian.PutUint16(udp[4:], uint16(len(udp)))
	copy(udp[8:], query)
	inject(link, ipPacket(net.ParseIP(DNSAddress), 17, udp))
	response := nextPacket(t, ctx, link)
	var answer dnsmessage.Message
	if answer.Unpack(response[28:]) != nil || answer.ID != 1234 || len(answer.Answers) != 1 {
		t.Fatal("invalid DNS response")
	}
	if !net.IP(response[12:16]).Equal(net.ParseIP(DNSAddress)) || binary.BigEndian.Uint16(response[22:]) != 40000 {
		t.Fatal("DNS source translation failed")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 2 {
		t.Fatal("netstack DNS did not fall back")
	}
	if _, action, err := h.target("1.2.3.4:443"); err != nil || action != routing.Proxy {
		t.Fatal("DNS metadata was not applied before the response", action, err)
	}
}
func TestNetstackDNSFallsBackToTCP(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	upstream := tcpDNSFixture(t, dnsmessage.RCodeSuccess)
	h := NewHandler(ctx)
	h.DNS = []string{"203.0.113.1"}
	h.UDP = packetListenerFunc(func(context.Context) (net.PacketConn, error) { return nil, fmt.Errorf("UDP unavailable") })
	h.TCP = transport.FuncStreamDialer(func(ctx context.Context, _ string) (transport.StreamConn, error) {
		return (&transport.TCPDialer{}).DialStream(ctx, upstream)
	})
	var events []string
	h.Report = func(code, _ string) { events = append(events, code) }
	link := testStack(t, h)
	query := dnsQuery(t)
	udp := make([]byte, 8+len(query))
	binary.BigEndian.PutUint16(udp, 40000)
	binary.BigEndian.PutUint16(udp[2:], 53)
	binary.BigEndian.PutUint16(udp[4:], uint16(len(udp)))
	copy(udp[8:], query)
	inject(link, ipPacket(net.ParseIP(DNSAddress), 17, udp))
	response := nextPacket(t, ctx, link)
	var answer dnsmessage.Message
	if answer.Unpack(response[28:]) != nil || len(answer.Answers) != 1 || !reflect.DeepEqual(events, []string{"dns_tcp_fallback"}) {
		t.Fatalf("TCP DNS fallback failed: answer=%v events=%v", answer, events)
	}
}
func TestDNSFailureAnswer(t *testing.T) {
	var response dnsmessage.Message
	if response.Unpack(dnsFailure(dnsQuery(t))) != nil || response.RCode != dnsmessage.RCodeServerFailure {
		t.Fatal("missing SERVFAIL response")
	}
}

func TestDisableIPv6DNS(t *testing.T) {
	var query dnsmessage.Message
	if err := query.Unpack(dnsQuery(t)); err != nil {
		t.Fatal(err)
	}
	query.Questions[0].Type = dnsmessage.TypeAAAA
	packet, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	for _, tcp := range []bool{false, true} {
		answer, err := (DNSResolver{DisableIPv6: true}).Exchange(context.Background(), packet, tcp)
		if err != nil {
			t.Fatal(err)
		}
		var response dnsmessage.Message
		if err := response.Unpack(answer); err != nil {
			t.Fatal(err)
		}
		if !response.Response || response.ID != query.ID || response.RCode != dnsmessage.RCodeSuccess || len(response.Answers) != 0 || !reflect.DeepEqual(response.Questions, query.Questions) {
			t.Fatal("invalid AAAA empty response")
		}
	}
	// A queries still use the upstream transport.
	if _, err := (DNSResolver{DisableIPv6: true}).Exchange(context.Background(), dnsQuery(t), false); err == nil {
		t.Fatal("A query incorrectly suppressed")
	}
}
