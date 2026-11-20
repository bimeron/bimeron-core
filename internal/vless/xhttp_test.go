package vless

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"bimeron/internal/accesskey"
	"bimeron/internal/vpn"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

func TestXHTTPReadDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	x := &xhttpConn{ctx: ctx, cancel: cancel, ready: make(chan struct{})}
	if err := x.SetReadDeadline(time.Now().Add(10 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	if _, err := x.Read(b[:]); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("deadline: %v", err)
	}
}

func TestXHTTPUploadStatusReachesReader(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		<-r.Context().Done()
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	u, _ := url.Parse(server.URL + "/stream/")
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	tr := &http2.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} // test certificate
	defer tr.CloseIdleConnections()
	x := &xhttpConn{ctx: ctx, cancel: cancel, client: &http.Client{Transport: tr}, base: *u, mode: "packet-up", session: "session", upload: make(chan []byte, 1), ready: make(chan struct{})}
	defer x.Close()
	go x.download(x.sessionURL(""), nil)
	go x.uploadPackets()
	if _, err := x.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	_, err := x.Read(b[:])
	var status interface{ HTTPStatusCode() int }
	if !errors.As(err, &status) || status.HTTPStatusCode() != 502 {
		t.Fatalf("upload status lost: %v", err)
	}
}

func TestXHTTPUploadFailureReleasesBlockedWriter(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	x := &xhttpConn{ctx: ctx, cancel: cancel, mode: "packet-up", upload: make(chan []byte), ready: make(chan struct{})}
	defer x.Close()
	done := make(chan error, 1)
	go func() { _, err := x.Write([]byte("blocked")); done <- err }()
	x.failUpload(xhttpStatusError{502})
	select {
	case err := <-done:
		var status interface{ HTTPStatusCode() int }
		if !errors.As(err, &status) || status.HTTPStatusCode() != 502 {
			t.Fatalf("write: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("failed upload left writer blocked")
	}
}

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

func TestDNSAttemptWithStalledXHTTPHeader(t *testing.T) {
	for _, mode := range []string{"stream-one", "stream-up"} {
		for _, tcp := range []bool{false, true} {
			stage := "UDP write"
			if tcp {
				stage = "TCP dial"
			}
			t.Run(mode+"/"+stage, func(t *testing.T) {
				started := make(chan struct{}, 2)
				release := make(chan struct{})
				defer close(release)
				client := &Client{endpoint: accesskey.Endpoint{Host: "example.com", Port: 443},
					settings:    accesskey.VLESS{Network: "xhttp", XHTTPMode: mode},
					connections: make(map[*streamConn]struct{}), packets: make(map[*packetConn]struct{}),
					xhttpTransport: &http2.Transport{DialTLSContext: func(ctx context.Context, _, _ string, _ *tls.Config) (net.Conn, error) {
						started <- struct{}{}
						select {
						case <-ctx.Done():
						case <-release:
						}
						return nil, net.ErrClosed
					}},
				}
				defer client.Close()
				// One A question for a. No HTTP request body can be consumed until dialing succeeds.
				query := []byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 'a', 0, 0, 1, 0, 1}
				r := vpn.DNSResolver{TCP: client, UDP: client, Servers: []string{"192.0.2.1"}, Timeout: 150 * time.Millisecond}
				done := make(chan error, 1)
				go func() { _, err := r.Exchange(t.Context(), query, tcp); done <- err }()
				select {
				case <-started:
				case <-time.After(time.Second):
					t.Fatal("HTTP dial never started")
				}
				select {
				case err := <-done:
					if err == nil || !strings.Contains(err.Error(), stage+" timeout") {
						t.Fatalf("exchange: %v", err)
					}
				case <-time.After(time.Second):
					t.Fatal("DNS attempt remained in header setup after its deadline")
				}
			})
		}
	}
}

func TestXHTTPStreamSurvivesDialCancellation(t *testing.T) {
	for _, mode := range []string{"stream-one", "stream-up"} {
		t.Run(mode, func(t *testing.T) {
			const target = "192.0.2.1:53"
			header, err := requestHeader([16]byte{}, 1, target, "")
			if err != nil {
				t.Fatal(err)
			}
			uploaded := make(chan struct{})
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					frame := make([]byte, len(header)+1)
					if _, err := io.ReadFull(r.Body, frame); err != nil || !bytes.Equal(frame, append(header, 42)) {
						return
					}
					close(uploaded)
					if mode == "stream-up" {
						return
					}
				}
				select {
				case <-uploaded:
					_, _ = w.Write([]byte{0, 0, 42})
				case <-r.Context().Done():
				}
			}))
			server.EnableHTTP2 = true
			server.StartTLS()
			defer server.Close()
			client := &Client{endpoint: accesskey.Endpoint{Host: "localhost"}, settings: accesskey.VLESS{Network: "xhttp", XHTTPMode: mode, XHTTPHost: server.Listener.Addr().String()}, connections: make(map[*streamConn]struct{}), xhttpTransport: &http2.Transport{TLSClientConfig: server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()}}
			defer client.Close()
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			conn, err := client.DialStream(ctx, target)
			cancel()
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(time.Second))
			if _, err := conn.Write([]byte{42}); err != nil {
				t.Fatal(err)
			}
			var reply [1]byte
			if _, err := io.ReadFull(conn, reply[:]); err != nil || reply[0] != 42 {
				t.Fatalf("reply %v, %v", reply, err)
			}
		})
	}
}
