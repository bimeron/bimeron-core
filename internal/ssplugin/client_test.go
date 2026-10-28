package ssplugin

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"bimeron/internal/accesskey"
	"github.com/shadowsocks/go-shadowsocks2/socks"
	"golang.getoutline.org/sdk/transport/shadowsocks"
	"golang.org/x/net/websocket"
)

func localProfile(t *testing.T, address string, mux uint32) accesskey.Profile {
	t.Helper()
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portText)
	return accesskey.Profile{TCP: accesskey.Endpoint{Host: host, Port: port, Cipher: "aes-192-gcm", Secret: "test-only"}, SSPlugin: &accesskey.SSPlugin{Host: "ws.example", Path: "/custom", Mux: mux}}
}

func TestSimpleObfsCannotUseWebSocketTransport(t *testing.T) {
	for _, mode := range []string{"http", "tls"} {
		settings, err := accesskey.ParseSSPlugin("obfs-local", "obfs="+mode)
		if err != nil {
			t.Fatal(err)
		}
		p := accesskey.Profile{TCP: accesskey.Endpoint{Host: "server.example", Port: 8388, Cipher: "aes-256-gcm", Secret: "test-only"}, SSPlugin: settings}
		if _, err := New(p, net.Dialer{}); err == nil || err.Error() != "simple-obfs transport is not implemented" {
			t.Fatalf("simple-obfs reached the WebSocket transport: %v", err)
		}
	}
}

func TestWebSocketHostPathAndAES192(t *testing.T) {
	key, err := shadowsocks.NewEncryptionKey("aes-192-gcm", "test-only")
	if err != nil {
		t.Fatal(err)
	}
	requests := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r.Host + r.URL.Path
		websocket.Handler(func(ws *websocket.Conn) {
			defer ws.Close()
			ws.PayloadType = websocket.BinaryFrame
			reader := shadowsocks.NewReader(ws, key)
			if _, err := socks.ReadAddr(reader); err != nil {
				return
			}
			_, _ = io.Copy(shadowsocks.NewWriter(ws, key), reader)
		}).ServeHTTP(w, r)
	}))
	defer server.Close()
	c, err := New(localProfile(t, strings.TrimPrefix(server.URL, "http://"), 0), net.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	conn, err := c.DialStream(t.Context(), "echo.example:80")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err = roundTrip(conn, []byte("AES192 over WebSocket")); err != nil {
		t.Fatal(err)
	}
	if request := <-requests; request != "ws.example/custom" {
		t.Fatalf("wrong Host or path: %q", request)
	}
	c.Close()
	if _, err = c.DialStream(t.Context(), "echo.example:80"); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed transport accepted a new stream: %v", err)
	}
}

func TestCloseCancelsWebSocketSetup(t *testing.T) {
	for _, mux := range []uint32{0, 8} {
		t.Run(strconv.Itoa(int(mux)), func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			accepted := make(chan net.Conn, 1)
			go func() {
				conn, err := listener.Accept()
				if err == nil {
					accepted <- conn
				}
			}()
			c, err := New(localProfile(t, listener.Addr().String(), mux), net.Dialer{})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			done := make(chan error, 1)
			go func() {
				conn, err := c.DialStream(context.Background(), "echo.example:80")
				if conn != nil {
					conn.Close()
				}
				done <- err
			}()
			select {
			case raw := <-accepted:
				defer raw.Close()
			case <-time.After(time.Second):
				t.Fatal("setup never connected")
			}
			c.Close()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("setup survived transport close")
				}
			case <-time.After(time.Second):
				t.Fatal("transport close did not cancel handshake")
			}
		})
	}
}

func TestConstructorRejectsInvalidProfiles(t *testing.T) {
	p := localProfile(t, "127.0.0.1:443", 1)
	for _, mutate := range []func(*accesskey.Profile){func(p *accesskey.Profile) { p.Type = "trojan" }, func(p *accesskey.Profile) { p.SSPlugin = nil }, func(p *accesskey.Profile) { p.TCP.Cipher = "unknown" }, func(p *accesskey.Profile) {
		p.ShadowTLS = &accesskey.ShadowTLS{ServerName: "handshake.example", Password: "outer-secret"}
	}} {
		copy := p
		mutate(&copy)
		if c, err := New(copy, net.Dialer{}); err == nil {
			c.Close()
			t.Fatal("accepted invalid plugin profile")
		}
	}
}
