package core

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	"bimeron/internal/accesskey"
	"bimeron/internal/config"
	"bimeron/internal/proxy"
	"bimeron/internal/testutil"
)

func TestShadowTLSBootstrapHasNoNativeUDP(t *testing.T) {
	c := DefaultConfig()
	c.Resolve = func(context.Context) (Profile, error) {
		return Profile{TCP: Endpoint{Host: "127.0.0.1", Port: 443, Cipher: "aes-256-gcm", Secret: "inner"},
			UDP: Endpoint{Host: "must-not-resolve.invalid", Port: 53}, ShadowTLS: &accesskey.ShadowTLS{ServerName: "handshake.example", Password: "outer"}}, nil
	}
	p, _, endpoints, err := resolveOnPath(t.Context(), c, networkPath{dialer: net.Dialer{}})
	if err != nil {
		t.Fatal(err)
	}
	if !p.TCPOnly() || endpoints.udp != "" || endpoints.udpName != "" || p.ShadowTLS.ServerName != "handshake.example" {
		t.Fatal("wrapped upstream exposed native UDP or lost its handshake name")
	}
}

func TestShadowTLSRejectsDirectAPIMisconfiguration(t *testing.T) {
	c := DefaultConfig()
	c.Resolve = func(context.Context) (Profile, error) {
		return Profile{Type: "socks5", TCP: Endpoint{Host: "127.0.0.1", Port: 1080}, ShadowTLS: &accesskey.ShadowTLS{ServerName: "handshake.example", Password: "outer"}}, nil
	}
	if _, _, _, err := resolveOnPath(t.Context(), c, networkPath{}); err == nil {
		t.Fatal("VPN accepted a plaintext wrapped profile")
	}
	if session, err := (proxyBackend{}).Open(t.Context(), c, func(string, string) {}); err == nil {
		_ = session.Close()
		t.Fatal("proxy mode ignored invalid wrapper settings")
	}
}

func TestShadowTLSBootstrapStreamUDPUsesWrappedTCP(t *testing.T) {
	c := DefaultConfig()
	c.Resolve = func(context.Context) (Profile, error) {
		return Profile{Type: "anytls", TCP: Endpoint{Host: "127.0.0.1", Port: 443}, UDP: Endpoint{Host: "must-not-resolve.invalid", Port: 53},
			AnyTLS: accesskey.AnyTLS{Password: "inner", ServerName: "backend.example"}, ShadowTLS: &accesskey.ShadowTLS{ServerName: "handshake.example", Password: "outer"}}, nil
	}
	p, _, endpoints, err := resolveOnPath(t.Context(), c, networkPath{})
	if err != nil {
		t.Fatal(err)
	}
	if p.TCPOnly() || p.UDP.Host != p.TCP.Host || p.UDP.Port != p.TCP.Port || endpoints.udp != endpoints.tcp {
		t.Fatal("UDP-over-stream does not describe the wrapped TCP endpoint")
	}
}

func TestShadowTLSConfigSnapshot(t *testing.T) {
	file, err := config.ParseData([]byte("[Profile]\nVersion=1\n[AccessKey]\nSS=ss://aes-256-gcm:inner@127.0.0.1:443\n[ShadowTLS]\nServerName=handshake.example\nPassword=outer\n"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := FromConfig(file)
	if err != nil {
		t.Fatal(err)
	}
	file.ShadowTLS.Password = "mutated"
	p, err := c.Resolve(t.Context())
	if err != nil || p.ShadowTLS.Password != "outer" {
		t.Fatal("session config did not snapshot wrapper settings")
	}
}

func TestShadowTLSProxyEngine(t *testing.T) {
	if os.Getenv("BIMERON_SHADOWTLS_BIN") == "" {
		t.Skip("set BIMERON_SHADOWTLS_BIN and BIMERON_XRAY_BIN")
	}
	backend := testutil.StartXray(t, "shadowsocks", map[string]any{"method": "aes-256-gcm", "password": "test-inner-password", "network": "tcp"}, nil)
	server := testutil.StartShadowTLS(t, backend)
	testutil.TrustShadowTLS(t, server)
	listen := net.JoinHostPort("127.0.0.1", strconv.Itoa(testutil.FreePort(t)))
	data := fmt.Sprintf("[Profile]\nVersion=1\n[AccessKey]\nSS=ss://aes-256-gcm:test-inner-password@%s\n[ShadowTLS]\nServerName=%s\nPassword=%s\n[Interface]\nMode=proxy\nListen=%s\n", server.Address, server.Settings.ServerName, server.Settings.Password, listen)
	c, err := LoadConfigData([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	engine := New(Options{})
	defer engine.Stop(context.Background())
	if err := engine.Start(t.Context(), c); err != nil {
		t.Fatal(err)
	}
	awaitState(t, engine, Connected)
	status := engine.Status()
	if status.Session == nil || status.Session.ServerTCP != server.Address || status.Session.ServerUDP != "" {
		t.Fatal("session status does not describe public wrapped endpoint")
	}
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "wrapped engine response") }))
	defer origin.Close()
	host, portText, _ := net.SplitHostPort(listen)
	port, _ := strconv.Atoi(portText)
	socks := &proxy.SOCKS5{Endpoint: Endpoint{Host: host, Port: port}}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, address string) (net.Conn, error) { return socks.DialStream(ctx, address) }}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	response, err := client.Get(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || string(body) != "wrapped engine response" {
		t.Fatalf("engine proxy response: %v", err)
	}
}
