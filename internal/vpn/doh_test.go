package vpn

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"

	"bimeron/internal/dnsconfig"
	"golang.getoutline.org/sdk/transport"
	"golang.org/x/net/dns/dnsmessage"
)

func testDoH(t testing.TB, rcode dnsmessage.RCode) (*DoHResolver, []byte, *atomic.Int64) {
	t.Helper()
	name := dnsmessage.MustNewName("example.test.")
	query, err := (&dnsmessage.Message{Header: dnsmessage.Header{ID: 42}, Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}).Pack()
	if err != nil {
		t.Fatal(err)
	}
	attempts := new(atomic.Int64)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.Header.Get("Content-Type") != dnsMediaType || r.URL.Path != "/dns-query" {
			w.WriteHeader(400)
			return
		}
		b, err := io.ReadAll(r.Body)
		var m dnsmessage.Message
		if err != nil || m.Unpack(b) != nil {
			w.WriteHeader(400)
			return
		}
		m.Response, m.RCode = true, rcode
		b, err = m.Pack()
		if err != nil {
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Type", dnsMediaType)
		_, _ = w.Write(b)
	}))
	t.Cleanup(server.Close)
	cert := server.Certificate()
	host := cert.DNSNames[0]
	dial := checkStreamDialer(func(ctx context.Context, address string) (transport.StreamConn, error) {
		attempts.Add(1)
		if address != "192.0.2.2:443" {
			return nil, net.ErrClosed
		}
		c, err := (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
		if err != nil {
			return nil, err
		}
		return c.(*net.TCPConn), nil
	})
	endpoints := []dnsconfig.DoHEndpoint{
		{URL: "https://" + host + "/dns-query", IPs: []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")}},
		{URL: "https://other.example/dns-query", IPs: []netip.Addr{netip.MustParseAddr("192.0.2.3")}},
	}
	resolver := NewDoHResolver(dial, endpoints, false)
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	for _, target := range resolver.attempts {
		target.transport.TLSClientConfig = &tls.Config{RootCAs: roots}
	}
	t.Cleanup(resolver.Close)
	return resolver, query, attempts
}

func TestDoHRetryAndTerminalNXDOMAIN(t *testing.T) {
	resolver, query, dials := testDoH(t, dnsmessage.RCodeNameError)
	for range 2 {
		response, err := resolver.Exchange(context.Background(), query)
		var answer dnsmessage.Message
		if err != nil || answer.Unpack(response) != nil || answer.RCode != dnsmessage.RCodeNameError {
			t.Fatalf("DNS reply: %v %v", answer.RCode, err)
		}
	}
	if got := dials.Load(); got != 3 {
		t.Fatalf("expected two failed first IP dials and one reused TLS connection, got %d", got)
	}
}

func TestDoHTLSFailureHasNoPlainFallback(t *testing.T) {
	doh, query, dials := testDoH(t, dnsmessage.RCodeSuccess)
	doh.attempts[1].transport.TLSClientConfig = &tls.Config{ServerName: "wrong.example", RootCAs: doh.attempts[1].transport.TLSClientConfig.RootCAs}
	resolver := DNSResolver{DoH: doh, Servers: []string{"192.0.2.99"}, TCP: checkStreamDialer(func(context.Context, string) (transport.StreamConn, error) {
		t.Fatal("plain DNS attempted")
		return nil, net.ErrClosed
	})}
	_, err := resolver.Exchange(context.Background(), query, true)
	if err == nil || !strings.Contains(err.Error(), "all DoH") || dials.Load() != 3 {
		t.Fatalf("failure = %v, dials = %d", err, dials.Load())
	}
}

func BenchmarkDoHExchange(b *testing.B) {
	doh, query, _ := testDoH(b, dnsmessage.RCodeSuccess)
	successful := &DoHResolver{attempts: doh.attempts[1:2]}
	for _, mode := range []string{"pooled", "cold", "failover", "concurrent"} {
		b.Run(mode, func(b *testing.B) {
			b.ReportAllocs()
			resolver := successful
			if mode == "failover" {
				resolver = doh
			}
			if mode == "concurrent" {
				b.RunParallel(func(pb *testing.PB) {
					for pb.Next() {
						if _, err := resolver.Exchange(context.Background(), query); err != nil {
							b.Error(err)
							return
						}
					}
				})
				return
			}
			for range b.N {
				if mode == "cold" {
					resolver.Close()
				}
				if _, err := resolver.Exchange(context.Background(), query); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
