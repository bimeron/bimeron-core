package core

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"bimeron/internal/accesskey"
	"bimeron/internal/telemetry"
	"bimeron/internal/vpn"
)

func TestVLESSProxyReferenceServer(t *testing.T) {
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
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "proxy-ok") }))
	defer target.Close()
	host, portText, _ := net.SplitHostPort(strings.TrimPrefix(target.URL, "http://"))
	port, _ := strconv.Atoi(portText)
	c := DefaultConfig()
	c.Mode, c.Listen = "proxy", "127.0.0.1:0"
	c.Resolve = func(context.Context) (Profile, error) { return p, nil }
	c.stats = &telemetry.Counters{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	session, err := (proxyBackend{}).Open(ctx, c, func(string, string) {})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	listener := session.(*proxySession).listener.Addr().String()
	conn, err := net.DialTimeout("tcp", listener, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	var choice [2]byte
	if _, err := io.ReadFull(conn, choice[:]); err != nil || choice != [2]byte{5, 0} {
		t.Fatalf("SOCKS negotiation failed: %v", err)
	}
	request := append([]byte{5, 1, 0, 1}, net.ParseIP(host).To4()...)
	request = binary.BigEndian.AppendUint16(request, uint16(port))
	if _, err := conn.Write(request); err != nil {
		t.Fatal(err)
	}
	var reply [10]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil || reply[1] != 0 {
		t.Fatalf("SOCKS CONNECT failed: %v", err)
	}
	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(conn)
	if err != nil || !strings.Contains(string(b), "proxy-ok") {
		t.Fatalf("proxied HTTP failed: %v", err)
	}
}

func TestVLESSVPNPrepareReferenceServer(t *testing.T) {
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
	c := DefaultConfig()
	c.Resolve = func(context.Context) (Profile, error) { return p, nil }
	c.stats = &telemetry.Counters{}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	h, _, _, closeTransport, err := prepareVPN(ctx, ctx, c, networkPath{dialer: net.Dialer{Timeout: 5 * time.Second}, dns: []string{"1.1.1.1"}}, func(string, string) {}, vpn.NewDNSMetadata())
	if err != nil {
		t.Fatalf("VLESS VPN transport precheck failed: %v", err)
	}
	h.Close()
	if closeTransport != nil {
		_ = closeTransport()
	}
}

func TestVLESSIPv6Bootstrap(t *testing.T) {
	c := DefaultConfig()
	c.Resolve = func(context.Context) (Profile, error) {
		e := Endpoint{Host: "2001:db8::1", Port: 443}
		return Profile{Type: "vless", TCP: e, UDP: e}, nil
	}
	p, _, endpoints, err := resolveOnPath(t.Context(), c, networkPath{dialer: net.Dialer{}, dns: []string{"1.1.1.1"}})
	if err != nil || p.TCP.Host != "2001:db8::1" || endpoints.tcp != "[2001:db8::1]:443" {
		t.Fatalf("VLESS IPv6 bootstrap failed: %v", err)
	}
}
