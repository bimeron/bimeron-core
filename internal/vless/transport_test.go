package vless

import (
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"bimeron/internal/accesskey"
	"golang.org/x/net/websocket"
)

func TestWebSocketTransport(t *testing.T) {
	server := httptest.NewServer(websocket.Handler(func(conn *websocket.Conn) {
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}))
	defer server.Close()
	address := strings.TrimPrefix(server.URL, "http://")
	conn, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	client := &Client{endpoint: accesskey.Endpoint{Host: address}, settings: accesskey.VLESS{WSPath: "/"}}
	ws, err := client.webSocket(conn, nil)
	if err != nil {
		conn.Close()
		t.Fatal(err)
	}
	defer ws.Close()
	if _, err := ws.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	var b [5]byte
	if _, err := io.ReadFull(ws, b[:]); err != nil || string(b[:]) != "hello" {
		t.Fatalf("WebSocket round trip: %v", err)
	}
}

func TestHTTPTransportsOwnedByClient(t *testing.T) {
	c := &Client{endpoint: accesskey.Endpoint{Host: "example.com", Port: 443}, settings: accesskey.VLESS{Security: "tls", ServerName: "example.com"}, connections: make(map[*streamConn]struct{}), packets: make(map[*packetConn]struct{})}
	g1, err := c.grpcClient()
	if err != nil {
		t.Fatal(err)
	}
	g2, err := c.grpcClient()
	if err != nil || g1 != g2 {
		t.Fatalf("gRPC client was not reused: %v", err)
	}
	h1, err := c.xhttpClientTransport()
	if err != nil {
		t.Fatal(err)
	}
	h2, err := c.xhttpClientTransport()
	if err != nil || h1 != h2 {
		t.Fatalf("XHTTP transport was not reused: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.grpcClient(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("gRPC reopened after close: %v", err)
	}
	if _, err := c.xhttpClientTransport(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("XHTTP reopened after close: %v", err)
	}
}

func TestWebSocketEarlyData(t *testing.T) {
	seen := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get("Sec-WebSocket-Protocol")
		websocket.Handler(func(conn *websocket.Conn) { _ = conn.Close() }).ServeHTTP(w, r)
	}))
	defer server.Close()
	address := strings.TrimPrefix(server.URL, "http://")
	conn, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	client := &Client{endpoint: accesskey.Endpoint{Host: address}, settings: accesskey.VLESS{WSPath: "/"}}
	ws, err := client.webSocket(conn, []byte("early-vless-header"))
	if err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	defer ws.Close()
	if got := <-seen; got != base64.RawURLEncoding.EncodeToString([]byte("early-vless-header")) {
		t.Fatalf("unexpected early data header: %q", got)
	}
}

func TestTLSRejectsUntrustedCertificate(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	raw, err := net.Dial("tcp", strings.TrimPrefix(server.URL, "https://"))
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	client := &Client{settings: accesskey.VLESS{ServerName: "localhost"}}
	if _, err := client.tlsHandshake(t.Context(), raw); err == nil {
		t.Fatal("accepted untrusted TLS certificate")
	}
}
