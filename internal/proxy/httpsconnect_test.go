package proxy

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"bimeron/internal/accesskey"
)

func httpsCertificate(t testing.TB, expired bool) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "HTTPS CONNECT test"},
		DNSNames: []string{"proxy.example.com"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if expired {
		template.NotAfter = now.Add(-time.Minute)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert}, roots
}

func httpsTestProxy(t testing.TB, expired bool, handler http.Handler) (*HTTPConnect, *httptest.Server) {
	t.Helper()
	cert, roots := httpsCertificate(t, expired)
	s := httptest.NewUnstartedServer(handler)
	s.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12}
	s.StartTLS()
	t.Cleanup(s.Close)
	return &HTTPConnect{
		Endpoint: accesskey.Endpoint{Host: "127.0.0.1", Port: s.Listener.Addr().(*net.TCPAddr).Port, Secret: "secret"},
		Username: "alice", ServerName: "proxy.example.com", rootCAs: roots,
		Dialer: net.Dialer{Timeout: time.Second},
	}, s
}

func TestHTTPSConnectAuthAndHalfClose(t *testing.T) {
	for _, credentials := range []string{"valid", "anonymous", "wrong", "missing"} {
		t.Run(credentials, func(t *testing.T) {
			serverErr := make(chan error, 1)
			p, _ := httpsTestProxy(t, false, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				expected := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:secret"))
				if credentials == "anonymous" {
					expected = ""
				}
				if r.Header.Get("Proxy-Authorization") != expected {
					w.WriteHeader(http.StatusProxyAuthRequired)
					return
				}
				if r.Method != http.MethodConnect || r.Host != "destination.example:443" || r.ProtoMajor != 1 || r.TLS.ServerName != "proxy.example.com" || r.TLS.NegotiatedProtocol != "http/1.1" {
					t.Error("incorrect CONNECT request or TLS identity")
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				c, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					serverErr <- err
					return
				}
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				_, err = io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\nhello")
				if err == nil {
					var body []byte
					body, err = io.ReadAll(c)
					if err == nil && string(body) != "ping" {
						err = errors.New("incorrect upload")
					}
				}
				if err == nil {
					_, err = io.WriteString(c, "pong")
				}
				serverErr <- err
			}))
			if credentials == "anonymous" || credentials == "missing" {
				p.Username, p.Endpoint.Secret = "", ""
			}
			if credentials == "wrong" {
				p.Endpoint.Secret = "wrong"
			}
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			c, err := p.DialStream(ctx, "destination.example:443")
			if credentials == "wrong" || credentials == "missing" {
				if err == nil {
					c.Close()
					t.Fatal("authentication failure accepted")
				}
				if !strings.Contains(err.Error(), "407") || strings.Contains(err.Error(), "secret") {
					t.Fatalf("authentication error: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(3 * time.Second))
			if _, err = io.WriteString(c, "ping"); err != nil {
				t.Fatal(err)
			}
			if err = c.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			var body strings.Builder
			if _, err = io.Copy(&body, c); err != nil || body.String() != "hellopong" {
				t.Fatalf("tunnel response: %q, %v", body.String(), err)
			}
			if err := <-serverErr; err != nil {
				t.Fatal(err)
			}
			if err := c.CloseRead(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestHTTPSConnectRejectsInvalidCertificates(t *testing.T) {
	for _, kind := range []string{"untrusted", "system-untrusted", "hostname", "expired"} {
		t.Run(kind, func(t *testing.T) {
			var requests atomic.Int32
			p, _ := httpsTestProxy(t, kind == "expired", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(200) }))
			if kind == "untrusted" {
				p.rootCAs = x509.NewCertPool()
			}
			if kind == "system-untrusted" {
				p.rootCAs = nil
			}
			if kind == "hostname" {
				p.ServerName = "wrong.example.com"
			}
			c, err := p.DialStream(t.Context(), "example.com:443")
			if err == nil {
				c.Close()
				t.Fatal("invalid certificate accepted")
			}
			var unknown x509.UnknownAuthorityError
			var hostname x509.HostnameError
			var invalid x509.CertificateInvalidError
			if ((kind == "untrusted" || kind == "system-untrusted") && !errors.As(err, &unknown)) || (kind == "hostname" && !errors.As(err, &hostname)) || (kind == "expired" && (!errors.As(err, &invalid) || invalid.Reason != x509.Expired)) {
				t.Fatalf("wrong verification error: %v", err)
			}
			if requests.Load() != 0 {
				t.Fatal("CONNECT or credentials sent before TLS verification")
			}
		})
	}
}

func TestHTTPSConnectCancellation(t *testing.T) {
	for _, stage := range []string{"handshake", "headers", "handshake-deadline", "headers-deadline"} {
		t.Run(stage, func(t *testing.T) {
			cert, roots := httpsCertificate(t, false)
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			ready, done := make(chan struct{}), make(chan struct{})
			go func() {
				defer close(done)
				raw, err := l.Accept()
				if err != nil {
					return
				}
				defer raw.Close()
				_ = raw.SetDeadline(time.Now().Add(3 * time.Second))
				var c net.Conn = raw
				if strings.HasPrefix(stage, "headers") {
					c = tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{cert}})
					if _, err := http.ReadRequest(bufio.NewReader(c)); err != nil {
						return
					}
				}
				close(ready)
				_, _ = io.Copy(io.Discard, c)
			}()
			p := HTTPConnect{Endpoint: accesskey.Endpoint{Host: "127.0.0.1", Port: l.Addr().(*net.TCPAddr).Port}, ServerName: "proxy.example.com", rootCAs: roots}
			ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
			defer cancel()
			result := make(chan error, 1)
			go func() {
				c, err := p.DialStream(ctx, "example.com:443")
				if c != nil {
					c.Close()
				}
				result <- err
			}()
			select {
			case <-ready:
			case <-time.After(3 * time.Second):
				t.Fatal("proxy did not reach setup stage")
			}
			if !strings.HasSuffix(stage, "-deadline") {
				cancel()
			}
			select {
			case err := <-result:
				if err == nil {
					t.Fatal("cancellation ignored")
				}
			case <-time.After(time.Second):
				t.Fatal("setup did not cancel promptly")
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("cancelled connection was not closed")
			}
		})
	}
}

func BenchmarkHTTPSConnect(b *testing.B) {
	p, _ := httpsTestProxy(b, false, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\n\r\n")
		_, _ = io.Copy(io.Discard, c)
	}))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		c, err := p.DialStream(b.Context(), "example.com:443")
		if err != nil {
			b.Fatal(err)
		}
		c.Close()
	}
}
