package vless

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"bimeron/internal/accesskey"
)

// Set BIMERON_VLESS_FIXTURE to a local, ignored URI file and run a reference server.
func TestReferenceServer(t *testing.T) {
	path := os.Getenv("BIMERON_VLESS_FIXTURE")
	if path == "" {
		t.Skip("reference server not configured")
	}
	uri, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("could not read fixture")
	}
	p, err := accesskey.ParseVLESS(strings.TrimSpace(string(uri)))
	if err != nil {
		t.Fatal("invalid fixture")
	}
	c, err := New(p, net.Dialer{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()

	wantBody := bytes.Repeat([]byte("vision-ok"), 32768)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(wantBody) }))
	defer server.Close()
	address := strings.TrimPrefix(server.URL, "https://")
	stream, err := c.DialStream(ctx, address)
	if err != nil {
		t.Fatalf("VLESS dial failed: %v", err)
	}
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(10 * time.Second))
	tlsConn := tls.Client(stream, &tls.Config{ServerName: "example.com", InsecureSkipVerify: true}) // local ephemeral test certificate
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		t.Fatalf("inner TLS handshake failed: %v", err)
	}
	if _, err := io.WriteString(tlsConn, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(tlsConn), nil)
	if err != nil {
		t.Fatalf("response failed: %v", err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || !bytes.Equal(body, wantBody) {
		t.Fatalf("unexpected TCP response: %v", err)
	}

	echo, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		var b [256]byte
		for i := 0; i < 2; i++ {
			n, peer, e := echo.ReadFrom(b[:])
			if e != nil {
				return
			}
			_, _ = echo.WriteTo(b[:n], peer)
		}
	}()
	packet, err := c.ListenPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	_ = packet.SetDeadline(time.Now().Add(8 * time.Second))
	for i := 0; i < 2; i++ {
		if _, err := packet.WriteTo([]byte("xudp-ok"), echo.LocalAddr()); err != nil {
			t.Fatalf("XUDP write failed: %v", err)
		}
		var b [256]byte
		n, _, err := packet.ReadFrom(b[:])
		if err != nil || string(b[:n]) != "xudp-ok" {
			t.Fatalf("XUDP response failed: %v", err)
		}
	}
}
