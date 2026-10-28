package anytls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"bimeron/internal/accesskey"
)

// BIMERON_ANYTLS_BIN points to a reference server configured with a valid
// localhost certificate. Its default self-signed certificate has no DNS name.
func TestReferenceServer(t *testing.T) {
	address, roots, customPadding := referenceServer(t)
	p, err := accesskey.ParseAnyTLS("anytls://test-only-password@" + address + "?sni=localhost")
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(p, net.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	c.rootCAs = roots
	defer c.Close()
	untrusted, err := New(p, net.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	defer untrusted.Close()
	if conn, err := untrusted.DialStream(context.Background(), "127.0.0.1:1"); err == nil {
		_ = conn.Close()
		t.Fatal("untrusted TLS certificate accepted")
	}
	wrongName := p
	wrongName.AnyTLS.ServerName = "wrong.invalid"
	mismatch, err := New(wrongName, net.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	mismatch.rootCAs = roots
	defer mismatch.Close()
	if conn, err := mismatch.DialStream(context.Background(), "127.0.0.1:1"); err == nil {
		_ = conn.Close()
		t.Fatal("incorrect TLS server name accepted")
	}
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				var b [4]byte
				if _, err := io.ReadFull(conn, b[:]); err == nil {
					_, _ = conn.Write(b[:])
				}
			}()
		}
	}()
	for i := 0; i < 2; i++ {
		stream, err := c.DialStream(context.Background(), echo.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		_ = stream.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := stream.Write([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		var reply [4]byte
		if _, err := io.ReadFull(stream, reply[:]); err != nil || string(reply[:]) != "ping" {
			t.Fatalf("TCP echo %q, %v", reply, err)
		}
		if _, err := io.Copy(io.Discard, stream); err != nil {
			t.Fatal(err)
		}
		_ = stream.Close()
		c.mu.Lock()
		idle := len(c.idle)
		c.mu.Unlock()
		if idle != 1 {
			t.Fatalf("expected reusable AnyTLS session, got %d", idle)
		}
	}
	c.mu.Lock()
	updated := c.padding.text
	c.mu.Unlock()
	if updated != customPadding {
		t.Fatalf("padding update not applied: %q", updated)
	}
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	go func() {
		var b [256]byte
		for {
			n, addr, err := udp.ReadFrom(b[:])
			if err != nil {
				return
			}
			_, _ = udp.WriteTo(b[:n], addr)
		}
	}()
	packets, err := c.ListenPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer packets.Close()
	_ = packets.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := packets.WriteTo([]byte("udp"), udp.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	var b [16]byte
	n, from, err := packets.ReadFrom(b[:])
	if err != nil || string(b[:n]) != "udp" || !strings.HasSuffix(from.String(), ":"+strconv.Itoa(udp.LocalAddr().(*net.UDPAddr).Port)) {
		t.Fatalf("UDP echo %q, %v, %v", b[:n], from, err)
	}
}

func referenceServer(t testing.TB) (string, *x509.CertPool, string) {
	t.Helper()
	bin := os.Getenv("BIMERON_ANYTLS_BIN")
	if bin == "" {
		t.Skip("set BIMERON_ANYTLS_BIN for reference-server interoperability")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverPort := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	port := strconv.Itoa(serverPort)
	address := net.JoinHostPort("127.0.0.1", port)
	paddingFile := filepath.Join(t.TempDir(), "padding.txt")
	customPadding := "stop=3\n0=31-31\n1=80-80\n2=100-100"
	if err := os.WriteFile(paddingFile, []byte(customPadding), 0600); err != nil {
		t.Fatal(err)
	}
	server := exec.Command(bin, "-l", address, "-p", "test-only-password", "-padding-scheme", paddingFile)
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Process.Kill(); _ = server.Wait() })
	for i := 0; i < 100; i++ {
		conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			break
		}
		if i == 99 {
			t.Fatal("AnyTLS reference server did not start")
		}
		time.Sleep(30 * time.Millisecond)
	}
	// The fixture certificate is self-signed. Trust its public certificate only
	// in this test, then use the normal TLS hostname verification path.
	probe, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", address, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec -- test certificate discovery
	if err != nil {
		t.Fatal(err)
	}
	cert := probe.ConnectionState().PeerCertificates[0]
	_ = probe.Close()
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	if _, err := cert.Verify(x509.VerifyOptions{DNSName: "localhost", Roots: roots}); err != nil {
		t.Fatalf("fixture certificate has no valid localhost name: %v", err)
	}
	return address, roots, customPadding
}

// Measures a 16-byte TCP request and response through the reference server.
// The cold case includes TLS setup; the warm case reuses an idle AnyTLS session.
func BenchmarkReferenceServer(b *testing.B) {
	address, roots, _ := referenceServer(b)
	p, err := accesskey.ParseAnyTLS("anytls://test-only-password@" + address + "?sni=localhost")
	if err != nil {
		b.Fatal(err)
	}
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				var data [16]byte
				if _, err := io.ReadFull(conn, data[:]); err == nil {
					_, _ = conn.Write(data[:])
				}
			}()
		}
	}()
	for _, cold := range []bool{true, false} {
		name := "warm"
		if cold {
			name = "cold"
		}
		b.Run(name, func(b *testing.B) {
			var shared *Client
			if !cold {
				shared, err = New(p, net.Dialer{})
				if err != nil {
					b.Fatal(err)
				}
				shared.rootCAs = roots
				defer shared.Close()
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				c := shared
				if cold {
					c, err = New(p, net.Dialer{})
					if err != nil {
						b.Fatal(err)
					}
					c.rootCAs = roots
				}
				stream, err := c.DialStream(context.Background(), echo.Addr().String())
				if err != nil {
					b.Fatal(err)
				}
				_ = stream.SetDeadline(time.Now().Add(5 * time.Second))
				var data [16]byte
				if _, err := stream.Write(data[:]); err != nil {
					b.Fatal(err)
				}
				if _, err := io.ReadFull(stream, data[:]); err != nil {
					b.Fatal(err)
				}
				if _, err := io.Copy(io.Discard, stream); err != nil {
					b.Fatal(err)
				}
				_ = stream.Close()
				if cold {
					_ = c.Close()
				}
			}
		})
	}
}
