package core

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"bimeron/internal/accesskey"
	"bimeron/internal/config"
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

func TestWireGuardTextSetsAdapterMTUAndDNS(t *testing.T) {
	client := wgtest.NewKeyPair(t)
	server := wgtest.NewKeyPair(t)
	wg := "[Interface]\nPrivateKey = " + wgtest.B64(client.Private) + "\nAddress = 10.8.0.2/32\n%s[Peer]\nPublicKey = " + wgtest.B64(server.Public) + "\nEndpoint = 192.0.2.1:51820\nAllowedIPs = 0.0.0.0/0\n"
	dir := t.TempDir()
	for _, tc := range []struct {
		wgExtra, profileExtra string
		mtu                   int
		dns                   string
	}{
		{"MTU = 1300\nDNS = 10.8.0.1\n", "", 1300, "10.8.0.1"},
		{"", "", 1420, "1.1.1.1"},
		{"MTU = 9000\n", "", 1500, "1.1.1.1"},
		{"MTU = 1300\nDNS = 10.8.0.1\n", "[Interface]\nMTU = 1400\nDNS = 9.9.9.9\n", 1400, "9.9.9.9"},
	} {
		if err := os.WriteFile(filepath.Join(dir, "k.conf"), []byte(fmt.Sprintf(wg, tc.wgExtra)), 0o600); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "p.conf")
		if err := os.WriteFile(path, []byte("[Profile]\nVersion = 1\n[AccessKey]\nFile = k.conf\n"+tc.profileExtra), 0o600); err != nil {
			t.Fatal(err)
		}
		c, err := config.Load(path)
		if err != nil {
			t.Fatal(err)
		}
		s, err := FromConfig(c)
		if err != nil || s.MTU != tc.mtu || strings.Join(s.DNS, ",") != tc.dns {
			t.Fatalf("%q/%q: mtu %d dns %v err %v", tc.wgExtra, tc.profileExtra, s.MTU, s.DNS, err)
		}
	}
}
