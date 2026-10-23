package vless

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"bimeron/internal/accesskey"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

func TestXHTTPPacketUp(t *testing.T) {
	payload := make(chan []byte, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Referer") == "" || !strings.HasPrefix(r.URL.Path, "/stream/session/") && r.URL.Path != "/stream/session" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.Method == http.MethodPost {
			b, _ := io.ReadAll(r.Body)
			payload <- b
			w.WriteHeader(http.StatusOK)
			return
		}
		select {
		case b := <-payload:
			_, _ = w.Write(b)
		case <-r.Context().Done():
		}
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	u, err := url.Parse(server.URL + "/stream/")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	transport := &http2.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} // test server certificate
	defer transport.CloseIdleConnections()
	x := &xhttpConn{ctx: ctx, cancel: cancel, client: &http.Client{Transport: transport}, base: *u, mode: "packet-up", session: "session", upload: make(chan []byte, 4), ready: make(chan struct{})}
	go x.download(x.sessionURL(""), nil)
	go x.uploadPackets()
	defer x.Close()
	if n, err := x.Write([]byte("xhttp-ok")); err != nil || n != 8 {
		t.Fatalf("write: %d %v", n, err)
	}
	var got [8]byte
	if _, err := io.ReadFull(x, got[:]); err != nil || string(got[:]) != "xhttp-ok" {
		t.Fatalf("read: %q %v", got, err)
	}
}

func TestXHTTPStreamOne(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/grpc" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		var b [4096]byte
		for {
			n, err := r.Body.Read(b[:])
			if n > 0 {
				_, _ = w.Write(b[:n])
				w.(http.Flusher).Flush()
			}
			if err != nil {
				return
			}
		}
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	u, err := url.Parse(server.URL + "/stream/")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	transport := &http2.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} // test server certificate
	defer transport.CloseIdleConnections()
	x := &xhttpConn{ctx: ctx, cancel: cancel, client: &http.Client{Transport: transport}, base: *u, mode: "stream-one", ready: make(chan struct{})}
	x.reader, x.writer = io.Pipe()
	go x.download(x.base, x.reader)
	defer x.Close()
	if n, err := x.Write([]byte("stream-ok")); err != nil || n != 9 {
		t.Fatalf("write: %d %v", n, err)
	}
	var got [9]byte
	if _, err := io.ReadFull(x, got[:]); err != nil || string(got[:]) != "stream-ok" {
		t.Fatalf("read: %q %v", got, err)
	}
}

func TestXHTTPStreamUp(t *testing.T) {
	payload := make(chan []byte, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/stream/session" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.Method == http.MethodPost {
			var b [9]byte
			if _, err := io.ReadFull(r.Body, b[:]); err == nil {
				payload <- b[:]
			}
			w.WriteHeader(http.StatusOK)
			return
		}
		select {
		case b := <-payload:
			_, _ = w.Write(b)
		case <-r.Context().Done():
		}
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	u, err := url.Parse(server.URL + "/stream/")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	transport := &http2.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} // test server certificate
	defer transport.CloseIdleConnections()
	x := &xhttpConn{ctx: ctx, cancel: cancel, client: &http.Client{Transport: transport}, base: *u, mode: "stream-up", session: "session", ready: make(chan struct{})}
	x.reader, x.writer = io.Pipe()
	go x.download(x.sessionURL(""), nil)
	go x.uploadStream()
	defer x.Close()
	if n, err := x.Write([]byte("stream-up")); err != nil || n != 9 {
		t.Fatalf("write: %d %v", n, err)
	}
	var got [9]byte
	if _, err := io.ReadFull(x, got[:]); err != nil || string(got[:]) != "stream-up" {
		t.Fatalf("read: %q %v", got, err)
	}
}

func TestXHTTP3BoundTransport(t *testing.T) {
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer tlsServer.Close()
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h3Server := &http3.Server{TLSConfig: &tls.Config{Certificates: tlsServer.TLS.Certificates}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("h3-ok"))
	})}
	go func() { _ = h3Server.Serve(packet) }()
	defer h3Server.Close()
	cert, err := x509.ParseCertificate(tlsServer.TLS.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	client := &Client{endpoint: accesskey.Endpoint{Host: "127.0.0.1", Port: packet.LocalAddr().(*net.UDPAddr).Port}, settings: accesskey.VLESS{ServerName: "example.com", ALPN: "h3"}}
	transport, err := client.xhttpClientTransport()
	if err != nil {
		t.Fatal(err)
	}
	client.xhttpH3Transport.TLSClientConfig.RootCAs = roots
	outbound := client.xhttpPacket
	defer client.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := (&http.Client{Transport: transport}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil || string(b) != "h3-ok" {
		t.Fatalf("HTTP/3 response: %q %v", b, err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	_ = outbound.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := outbound.ReadFrom(make([]byte, 1)); err == nil {
		t.Fatal("HTTP/3 socket remained open after client close")
	}
}
