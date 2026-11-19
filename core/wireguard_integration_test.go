package core

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"bimeron/internal/accesskey"
	"bimeron/internal/proxy"
	"bimeron/internal/telemetry"
	"bimeron/internal/wgconf"
	"bimeron/internal/wireguard/wgtest"
)

func wireGuardProfile(t *testing.T, text string) Profile {
	t.Helper()
	cfg, err := wgconf.Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	return accesskey.WireGuardProfile("test", cfg)
}

func TestWireGuardProxyBackend(t *testing.T) {
	client := wgtest.NewKeyPair(t)
	p := wgtest.Profiles["awg-2.0"]
	s := wgtest.StartAWG(t, client, p.Server)
	profile := wireGuardProfile(t, s.ClientText(client, "10.77.0.0/24", p.Client...))
	cfg := DefaultConfig()
	cfg.Mode, cfg.Listen = "proxy", "127.0.0.1:0"
	cfg.AllowedIPsMode = "block"
	cfg.stats = &telemetry.Counters{}
	cfg.Resolve = func(context.Context) (Profile, error) { return profile, nil }
	var reports []string
	session, err := (proxyBackend{}).Open(t.Context(), cfg, func(code, _ string) { reports = append(reports, code) })
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if reports[0] != "wireguard_handshake" {
		t.Fatalf("reports %v", reports)
	}
	host, portText, _ := net.SplitHostPort(session.(*proxySession).listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	socks := &proxy.SOCKS5{Endpoint: accesskey.Endpoint{Host: host, Port: port}, Dialer: net.Dialer{Timeout: time.Second}}
	conn, err := socks.DialStream(t.Context(), "10.77.0.1:7")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("through-wireguard")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 17)
	if _, err := io.ReadFull(conn, got); err != nil || string(got) != "through-wireguard" {
		t.Fatalf("relay: %q %v", got, err)
	}
	// Block mode keeps destinations outside AllowedIPs out of the tunnel
	// and off the direct path.
	if outside, err := socks.DialStream(t.Context(), "127.0.0.1:9"); err == nil {
		outside.Close()
		t.Fatal("destination outside AllowedIPs was reachable in block mode")
	}
}

func TestWireGuardHandshakeTimeoutFault(t *testing.T) {
	client := wgtest.NewKeyPair(t)
	s := wgtest.StartAWG(t, client, nil)
	s.Key = wgtest.NewKeyPair(t)
	profile := wireGuardProfile(t, s.ClientText(client, "0.0.0.0/0"))
	ctx, cancel := context.WithTimeout(t.Context(), 1500*time.Millisecond)
	defer cancel()
	_, err := startWireGuard(ctx, DefaultConfig(), profile, net.Dialer{}, func(string, string) {})
	var staged *stageError
	if !errors.As(err, &staged) || staged.code != "wireguard_handshake_timeout" || !staged.retry {
		t.Fatalf("fault %v", err)
	}
}
