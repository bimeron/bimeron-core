package vless

import (
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
	ws, err := client.webSocket(conn)
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
