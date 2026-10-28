package naive

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"bimeron/internal/accesskey"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func testProxy(t testing.TB, protocol string, handler http.Handler) (accesskey.Profile, *x509.CertPool, *atomic.Int32) {
	return testProxyAt(t, protocol, "127.0.0.1", handler)
}

func testProxyAt(t testing.TB, protocol, host string, handler http.Handler) (accesskey.Profile, *x509.CertPool, *atomic.Int32) {
	t.Helper()
	fixture := httptest.NewUnstartedServer(handler)
	fixture.EnableHTTP2 = true
	connections := new(atomic.Int32)
	fixture.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	fixture.StartTLS()
	t.Cleanup(fixture.Close)
	roots := x509.NewCertPool()
	roots.AddCert(fixture.Certificate())
	port := fixture.Listener.Addr().(*net.TCPAddr).Port
	if protocol == "h3" {
		packet, err := net.ListenPacket("udp", net.JoinHostPort(host, "0"))
		if err != nil {
			t.Fatal(err)
		}
		port = packet.LocalAddr().(*net.UDPAddr).Port
		server := &http3.Server{TLSConfig: fixture.TLS.Clone(), Handler: handler, ConnContext: func(ctx context.Context, _ *quic.Conn) context.Context {
			connections.Add(1)
			return ctx
		}}
		done := make(chan error, 1)
		go func() { done <- server.Serve(packet) }()
		t.Cleanup(func() {
			_ = server.Close()
			_ = packet.Close()
			<-done
		})
	}
	return accesskey.Profile{Type: "naive", TCP: accesskey.Endpoint{Host: host, Port: port}, Naive: accesskey.Naive{User: "user", Password: "pass", ServerName: "example.com", QUIC: protocol == "h3"}}, roots, connections
}

func TestHTTP3IPv6(t *testing.T) {
	probe, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Skip("IPv6 loopback unavailable")
	}
	_ = probe.Close()
	profile, roots, _ := testProxyAt(t, "h3", "::1", http.HandlerFunc(echoTunnel))
	var bound atomic.Bool
	client, err := New(profile, net.Dialer{Control: func(network, _ string, _ syscall.RawConn) error {
		bound.Store(network == "udp6")
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	client.rootCAs = roots
	defer client.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	conn, err := client.DialStream(ctx, "[2001:db8::1]:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if !bound.Load() {
		t.Fatal("IPv6 socket control bypassed")
	}
}

func echoTunnel(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Padding", "reply-padding")
	w.WriteHeader(http.StatusOK)
	w.(http.Flusher).Flush()
	buf := make([]byte, 32768)
	for {
		n, err := r.Body.Read(buf)
		if n > 0 {
			if _, err := w.Write(buf[:n]); err != nil {
				return
			}
			w.(http.Flusher).Flush()
		}
		if err != nil {
			return
		}
	}
}

func TestHTTP3SocketControlAndReconnect(t *testing.T) {
	profile, roots, connections := testProxy(t, "h3", http.HandlerFunc(echoTunnel))
	var controlled atomic.Int32
	client, err := New(profile, net.Dialer{Control: func(network, _ string, _ syscall.RawConn) error {
		if network != "udp4" {
			return errors.New("unexpected socket family")
		}
		controlled.Add(1)
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	client.rootCAs = roots
	defer client.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	for i := 0; i < 2; i++ {
		conn, err := client.DialStream(ctx, "example.org:443")
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.Close()
		client.h3.CloseIdleConnections()
	}
	if controlled.Load() != 2 || connections.Load() != 2 {
		t.Fatalf("socket controls %d, connections %d", controlled.Load(), connections.Load())
	}
	_ = client.Close()
	if _, err := client.DialStream(ctx, "example.org:443"); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("dial after close: %v", err)
	}
}

func TestHTTP3ResolverAndTLSName(t *testing.T) {
	profile, roots, _ := testProxy(t, "h3", http.HandlerFunc(echoTunnel))
	profile.Naive.ServerName = "wrong.example"
	client, err := New(profile, net.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	client.rootCAs = roots
	defer client.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if _, err := client.DialStream(ctx, "example.org:443"); err == nil {
		t.Fatal("wrong TLS server name accepted")
	}
	client.mu.Lock()
	count := len(client.sockets)
	client.mu.Unlock()
	if count != 0 {
		t.Fatal("failed handshake leaked a UDP socket")
	}
	profile.TCP.Host = "proxy.invalid"
	var resolved atomic.Bool
	resolver := &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		resolved.Store(true)
		return nil, errors.New("test resolver unavailable")
	}}
	other, err := New(profile, net.Dialer{Resolver: resolver})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if _, err := other.DialStream(ctx, "example.org:443"); err == nil || !resolved.Load() {
		t.Fatal("configured resolver was bypassed")
	}
}

func TestHTTP3CancelHandshake(t *testing.T) {
	// A silent UDP peer keeps the QUIC handshake pending without external traffic.
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	profile := accesskey.Profile{Type: "naive", TCP: accesskey.Endpoint{Host: "127.0.0.1", Port: packet.LocalAddr().(*net.UDPAddr).Port}, Naive: accesskey.Naive{User: "user", Password: "pass", ServerName: "example.com", QUIC: true}}
	for _, closeClient := range []bool{false, true} {
		client, err := New(profile, net.Dialer{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = client.Close() })
		ctx, cancel := context.WithCancel(t.Context())
		result := make(chan error, 1)
		go func() { _, err := client.DialStream(ctx, "example.org:443"); result <- err }()
		_ = packet.SetReadDeadline(time.Now().Add(3 * time.Second))
		if _, _, err := packet.ReadFrom(make([]byte, 2048)); err != nil {
			cancel()
			t.Fatal(err)
		}
		if closeClient {
			_ = client.Close()
		}
		cancel()
		select {
		case err := <-result:
			if err == nil {
				t.Fatal("silent QUIC peer accepted")
			}
		case <-time.After(3 * time.Second):
			t.Fatal("pending handshake was not canceled")
		}
		_ = client.Close()
	}
}

func BenchmarkConnect(b *testing.B) {
	for _, protocol := range []string{"h2", "h3"} {
		b.Run(protocol, func(b *testing.B) {
			profile, roots, _ := testProxy(b, protocol, http.HandlerFunc(echoTunnel))
			client, err := New(profile, net.Dialer{})
			if err != nil {
				b.Fatal(err)
			}
			client.rootCAs = roots
			defer client.Close()
			conn, err := client.DialStream(b.Context(), "example.org:443")
			if err != nil {
				b.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(time.Minute))
			payload, response := make([]byte, 32768), make([]byte, 32768)
			b.SetBytes(int64(len(payload)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := conn.Write(payload); err != nil {
					b.Fatal(err)
				}
				if _, err := io.ReadFull(conn, response); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
		})
	}
}
