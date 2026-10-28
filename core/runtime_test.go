package core

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"bimeron/internal/accesskey"
	"bimeron/internal/hysteria2"
)

func TestUnavailableKeyStopsWithoutRetry(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusGone)
	}))
	defer server.Close()
	resolve := func(ctx context.Context) (Profile, error) {
		resolver := accesskey.NewResolverWithTransport(server.Client().Transport)
		return resolver.Resolve(ctx, "ssconf://"+strings.TrimPrefix(server.URL, "https://"))
	}
	for _, mode := range []string{"proxy", "vpn"} {
		t.Run(mode, func(t *testing.T) {
			cfg := testConfig()
			cfg.Mode = mode
			cfg.Resolve = resolve
			cfg.ResolveOnNetwork = func(ctx context.Context, _ http.RoundTripper) (Profile, error) { return resolve(ctx) }
			engine := New(Options{RetryMin: time.Millisecond})
			if mode == "vpn" {
				engine.factory = func(SessionConfig) backend { return &vpnBackend{platform: &inspectOnlyPlatform{}} }
			}
			ctx := testDeadline(t)
			if err := engine.Start(ctx, cfg); err != nil {
				t.Fatal(err)
			}
			if err := engine.Wait(ctx); err == nil || err.Error() != "access_key_unavailable" {
				t.Fatal(err)
			}
			status := engine.Status()
			if status.State != Failed || status.Attempt != 1 || status.LastError != "access_key_unavailable" {
				t.Fatal(status)
			}
		})
	}
}

func TestResolveSSHOnVPNPathPreservesHostKeyName(t *testing.T) {
	configuration := DefaultConfig()
	configuration.Resolve = func(context.Context) (Profile, error) {
		return Profile{Type: "ssh", TCP: Endpoint{Host: "ssh.example.com", Port: 22}, SSH: accesskey.SSH{User: "alice"}}, nil
	}
	profile, _, endpoints, err := resolveOnPath(t.Context(), configuration, networkPath{dialer: net.Dialer{}})
	if err != nil {
		t.Fatal(err)
	}
	if profile.TCP.Host != "ssh.example.com" || endpoints.tcp != "ssh.example.com:22" || endpoints.udp != "" {
		t.Fatalf("SSH name or TCP-only endpoint lost: %+v %+v", profile, endpoints)
	}
}

func TestResolveHTTPOnVPNPathHasOnlyTCPEndpoint(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Resolve = func(context.Context) (Profile, error) {
		return Profile{Type: "http", TCP: Endpoint{Host: "127.0.0.1", Port: 8080}}, nil
	}
	profile, _, endpoints, err := resolveOnPath(testDeadline(t), cfg, networkPath{dialer: net.Dialer{}})
	if err != nil {
		t.Fatal(err)
	}
	if profile.TCP.Host != "127.0.0.1" || endpoints.tcp != "127.0.0.1:8080" || endpoints.udp != "" || endpoints.udpName != "" {
		t.Fatalf("invalid TCP-only endpoint: %+v", endpoints)
	}
}

func TestResolveShadowsocksPluginOnVPNPathKeepsHostAndNoUDP(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Resolve = func(context.Context) (Profile, error) {
		return accesskey.ParseSS("ss://aes-256-gcm:secret@[::1]:443/?plugin=v2ray-plugin%3Btls%3Bhost%3Dws.example%3Bmux%3D8")
	}
	p, _, endpoints, err := resolveOnPath(t.Context(), cfg, networkPath{dialer: net.Dialer{}})
	if err != nil {
		t.Fatal(err)
	}
	if p.TCP.Host != "::1" || p.SSPlugin == nil || p.SSPlugin.Host != "ws.example" || endpoints.tcp != "[::1]:443" || endpoints.udp != "" || endpoints.udpName != "" {
		t.Fatalf("plugin transport endpoint or TLS host changed: %+v", endpoints)
	}
}

func TestResolveNaiveOnVPNPathKeepsTLSNameAndNoUDP(t *testing.T) {
	c := DefaultConfig()
	c.Resolve = func(context.Context) (Profile, error) {
		return accesskey.ParseNaive("naive+https://user:pass@[::1]:443?sni=example.com")
	}
	p, _, endpoints, err := resolveOnPath(t.Context(), c, networkPath{dialer: net.Dialer{}})
	if err != nil {
		t.Fatal(err)
	}
	if p.TCP.Host != "::1" || p.Naive.ServerName != "example.com" || endpoints.tcp != "[::1]:443" || endpoints.udp != "" {
		t.Fatalf("NaiveProxy TLS name or TCP-only endpoint lost: %+v %+v", p, endpoints)
	}
}

func TestResolveHTTPSOnVPNPathKeepsTLSName(t *testing.T) {
	c := DefaultConfig()
	c.DNS = nil
	c.Resolve = func(context.Context) (Profile, error) {
		p, err := accesskey.ParseHTTPConnect("https://proxy.example.com:443")
		// Model a resolved endpoint without relying on the runner's hosts file
		// or external DNS. Bootstrap must normalize the IP, not the TLS identity.
		p.TCP.Host = "0:0:0:0:0:0:0:1"
		return p, err
	}
	p, _, endpoints, err := resolveOnPath(t.Context(), c, networkPath{dialer: net.Dialer{}})
	if err != nil {
		t.Fatal(err)
	}
	if p.HTTPServerName != "proxy.example.com" || p.TCP.Host != "::1" || endpoints.tcp != "[::1]:443" || endpoints.udp != "" {
		t.Fatal("HTTPS identity or TCP-only behavior lost")
	}
}

func TestProxyEngineListenerLifecycle(t *testing.T) {
	// Only loopback is used; no DNS, external network, or system VPN operations.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := l.Addr().String()
	_ = l.Close()
	c := DefaultConfig()
	c.Mode = "proxy"
	c.Listen = address
	c.Resolve = func(context.Context) (Profile, error) {
		return Profile{TCP: Endpoint{Host: "127.0.0.1", Port: 9, Cipher: "aes-256-gcm", Secret: "test-only"}}, nil
	}
	e := New(Options{})
	ctx := testDeadline(t)
	defer e.Stop(context.Background())
	for i := 0; i < 2; i++ {
		if err := e.Start(ctx, c); err != nil {
			t.Fatal(err)
		}
		awaitState(t, e, Connected)
		if info := e.Status().Session; info == nil || info.ServerTCP != "127.0.0.1:9" || info.ServerUDP != "" {
			t.Fatal("SOCKS endpoint missing from session status", info)
		}
		conn, err := net.DialTimeout("tcp", address, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
			t.Fatal(err)
		}
		var answer [2]byte
		if _, err := io.ReadFull(conn, answer[:]); err != nil || answer != [2]byte{5, 0} {
			t.Fatal("SOCKS handshake", answer, err)
		}
		// A refused loopback upstream exercises the real SOCKS telemetry wiring.
		if _, err := conn.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1, 0, 9}); err != nil {
			t.Fatal(err)
		}
		var response [10]byte
		if _, err := io.ReadFull(conn, response[:]); err != nil {
			t.Fatal(err)
		}
		if snapshot := e.Stats(); snapshot.TCPTotal != 1 {
			t.Fatal("SOCKS statistics missing or not reset", snapshot)
		}
		if err := e.Stop(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Read(answer[:]); err == nil {
			t.Fatal("active client survived Stop")
		}
		_ = conn.Close()
		if c, err := net.DialTimeout("tcp", address, 100*time.Millisecond); err == nil {
			c.Close()
			t.Fatal("listener survived Stop")
		}
	}
}

func TestResolverErrorRedacted(t *testing.T) {
	c := DefaultConfig()
	c.Mode = "proxy"
	c.Resolve = func(context.Context) (Profile, error) {
		return Profile{}, errors.New("https://secret.example/ssconf/password")
	}
	e := New(Options{})
	ctx := testDeadline(t)
	if err := e.Start(ctx, c); err != nil {
		t.Fatal(err)
	}
	awaitState(t, e, Reconnecting)
	if got := e.Status().LastError; got != "access_key_resolve_failed" {
		t.Fatal(got)
	}
	if err := e.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	for {
		select {
		case event := <-e.Events():
			if strings.Contains(event.Message+event.LastError, "secret") {
				t.Fatal("credential leaked")
			}
		default:
			return
		}
	}
}

func TestHysteria2FailureContractBothModes(t *testing.T) {
	uri := "hysteria2://127.0.0.1:9?auth=synthetic-secret&sni=localhost&insecure=0&alpn=h3"
	p, err := accesskey.ParseHysteria2(uri)
	if err != nil {
		t.Fatal(err)
	}
	p.Hysteria2.Fingerprint = "unsupported-fingerprint"
	for _, mode := range []string{"proxy", "vpn"} {
		t.Run(mode, func(t *testing.T) {
			c := testConfig()
			c.Mode = mode
			c.Resolve = func(context.Context) (Profile, error) { return p, nil }
			c.ResolveOnNetwork = func(context.Context, http.RoundTripper) (Profile, error) { return p, nil }
			e := New(Options{RetryMin: time.Millisecond})
			if mode == "vpn" {
				e.factory = func(SessionConfig) backend { return &vpnBackend{platform: &inspectOnlyPlatform{}} }
			}
			ctx := testDeadline(t)
			if err := e.Start(ctx, c); err != nil {
				t.Fatal(err)
			}
			if err := e.Wait(ctx); err == nil || err.Error() != "hysteria2_invalid_config" {
				t.Fatal(err)
			}
			status := e.Status()
			if status.State != Failed || status.Attempt != 1 || status.LastError != "hysteria2_invalid_config" || status.ErrorStage != "configuration" {
				t.Fatal(status)
			}
			for len(e.Events()) > 0 {
				event := <-e.Events()
				if strings.Contains(event.Message+event.LastError+event.ErrorStage, "synthetic-secret") || strings.Contains(event.Message+event.LastError+event.ErrorStage, uri) {
					t.Fatal("credential leaked", event)
				}
				if event.State == Failed && (event.LastError != status.LastError || event.ErrorStage != status.ErrorStage) {
					t.Fatal(event)
				}
			}
		})
	}
}

func TestHysteria2FailureRetryability(t *testing.T) {
	if !errors.Is(hysteria2Fault(context.Canceled), context.Canceled) {
		t.Fatal("cancellation was converted to a transport failure")
	}
	for _, tc := range []struct {
		code, stage string
		retry       bool
	}{
		{"hysteria2_network_timeout", "connection", true},
		{"hysteria2_outbound_socket_failed", "outbound_socket", true},
		{"hysteria2_tls_failed", "tls", false},
		{"hysteria2_auth_rejected", "authentication", false},
		{"hysteria2_udp_disabled", "udp_capability", false},
		{"hysteria2_unknown", "connection", false},
	} {
		err := hysteria2Fault(&hysteria2.Failure{Code: tc.code, Stage: tc.stage, Retry: tc.retry})
		var staged *stageError
		if !errors.As(err, &staged) || err.Error() != tc.code || staged.stage != tc.stage || retryable(err) != tc.retry {
			t.Fatalf("%s: %v", tc.code, err)
		}
	}
}
