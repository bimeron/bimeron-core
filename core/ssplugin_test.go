package core

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"bimeron/internal/accesskey"
	"bimeron/internal/telemetry"
	"github.com/shadowsocks/go-shadowsocks2/socks"
	"golang.getoutline.org/sdk/transport/shadowsocks"
	"golang.org/x/net/websocket"
)

func TestShadowsocksPluginProxyRuntimeAndCleanup(t *testing.T) {
	key, err := shadowsocks.NewEncryptionKey("aes-256-gcm", "test-only")
	if err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewServer(websocket.Handler(func(ws *websocket.Conn) {
		defer ws.Close()
		ws.PayloadType = websocket.BinaryFrame
		r := shadowsocks.NewReader(ws, key)
		if _, err := socks.ReadAddr(r); err != nil {
			return
		}
		_, _ = io.Copy(shadowsocks.NewWriter(ws, key), r)
	}))
	defer upstream.Close()
	host, portText, _ := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "http://"))
	port, _ := strconv.Atoi(portText)
	p := Profile{TCP: Endpoint{Host: host, Port: port, Cipher: "aes-256-gcm", Secret: "test-only"}, SSPlugin: &accesskey.SSPlugin{Host: "ws.example", Path: "/", Mux: 0}}
	cfg := DefaultConfig()
	cfg.Mode, cfg.Listen = "proxy", "127.0.0.1:0"
	cfg.stats = &telemetry.Counters{}
	cfg.Resolve = func(context.Context) (Profile, error) { return p, nil }
	session, err := (proxyBackend{}).Open(t.Context(), cfg, func(string, string) {})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	listener := session.(*proxySession).listener.Addr().String()
	conn, err := net.Dial("tcp", listener)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	conn.Write([]byte{5, 1, 0})
	var choice [2]byte
	if _, err = io.ReadFull(conn, choice[:]); err != nil || choice != [2]byte{5, 0} {
		t.Fatal("SOCKS negotiation failed", err)
	}
	request := append([]byte{5, 1, 0, 3, 12}, []byte("echo.example")...)
	request = binary.BigEndian.AppendUint16(request, 80)
	if _, err = conn.Write(request); err != nil {
		t.Fatal(err)
	}
	var response [10]byte
	if _, err = io.ReadFull(conn, response[:]); err != nil || response[1] != 0 {
		t.Fatal("SOCKS CONNECT failed", err)
	}
	if _, err = conn.Write([]byte("runtime")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 7)
	if _, err = io.ReadFull(conn, reply); err != nil || string(reply) != "runtime" {
		t.Fatal("runtime did not use plugin", err)
	}
	if err = session.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = conn.Read(reply); err == nil {
		t.Fatal("client survived runtime close")
	}
}
