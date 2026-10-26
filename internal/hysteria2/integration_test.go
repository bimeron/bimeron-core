package hysteria2

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"strconv"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"bimeron/internal/accesskey"
	"github.com/apernet/hysteria/core/v2/server"
)

type testAuth struct{}

func (testAuth) Authenticate(_ net.Addr, auth string, _ uint64) (bool, string) {
	return auth == "secret", "test"
}

func testCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots.AddCert(parsed)
	return cert, roots
}

func TestReferenceServerTCPUDP(t *testing.T) {
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	go func() {
		for {
			c, err := tcp.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	go func() {
		b := make([]byte, 2048)
		for {
			n, addr, err := udp.ReadFrom(b)
			if err != nil {
				return
			}
			_, _ = udp.WriteTo(b[:n], addr)
		}
	}()
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cert, roots := testCertificate(t)
	s, err := server.NewServer(&server.Config{Conn: listener, TLSConfig: server.TLSConfig{Certificates: []tls.Certificate{cert}}, Authenticator: testAuth{}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go func() { _ = s.Serve() }()
	host, portText, _ := net.SplitHostPort(listener.LocalAddr().String())
	port, _ := strconv.Atoi(portText)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	p := accesskey.Profile{Type: "hysteria2", TCP: accesskey.Endpoint{Host: host, Port: port}, Hysteria2: accesskey.Hysteria2{Password: "secret", ServerName: "localhost"}}
	if bad, err := newClient(ctx, p, net.Dialer{}, nil); err == nil {
		_ = bad.Close()
		t.Fatal("untrusted certificate was accepted")
	}
	wrong := p
	wrong.Hysteria2.Password = "wrong"
	if bad, err := newClient(ctx, wrong, net.Dialer{}, roots); err == nil {
		_ = bad.Close()
		t.Fatal("incorrect password was accepted")
	}
	var bound atomic.Bool
	dialer := net.Dialer{Control: func(string, string, syscall.RawConn) error { bound.Store(true); return nil }}
	c, err := newClient(ctx, p, dialer, roots)
	if err != nil {
		t.Fatal(err)
	}
	if !bound.Load() {
		t.Fatal("outbound UDP socket did not use interface binding")
	}
	defer c.Close()
	stream, err := c.DialStream(ctx, tcp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = stream.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := stream.Write([]byte("tcp")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 3)
	if _, err := io.ReadFull(stream, b); err != nil || string(b) != "tcp" {
		t.Fatalf("TCP echo: %q, %v", b, err)
	}
	_ = stream.Close()
	packet, err := c.ListenPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	_ = packet.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := packet.WriteTo([]byte("udp"), udp.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	n, _, err := packet.ReadFrom(b)
	if err != nil || string(b[:n]) != "udp" {
		t.Fatalf("UDP echo: %q, %v", b[:n], err)
	}
}
