//go:build linux

package core

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/pprof"
	"strings"
	"testing"
	"time"

	"bimeron/internal/linuxnet"
	"bimeron/internal/masque"
	"bimeron/internal/masque/masquetest"
	"bimeron/internal/vpn"
	"golang.getoutline.org/sdk/transport"
)

type loopbackStream struct {
	address string
	dialer  transport.StreamDialer
}

func (d loopbackStream) DialStream(ctx context.Context, _ string) (transport.StreamConn, error) {
	dialer := d.dialer
	if dialer == nil {
		dialer = &transport.TCPDialer{}
	}
	return dialer.DialStream(ctx, d.address)
}

func TestLinuxTUNHTTP(t *testing.T)   { testLinuxTUNHTTP(t, false) }
func TestLinuxTUNMASQUE(t *testing.T) { testLinuxTUNHTTP(t, true) }

func testLinuxTUNHTTP(t *testing.T, useMASQUE bool) {
	if os.Getenv("BIMERON_NETNS_TEST") != "1" {
		t.Skip("requires unshare -n")
	}
	current, _ := os.Readlink("/proc/self/ns/net")
	host, _ := os.Readlink("/proc/1/ns/net")
	if os.Geteuid() != 0 || current == "" || current == host {
		t.Fatal("refusing to change host network namespace")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	runner := func(ctx context.Context, name, input string, args ...string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, name, args...)
		cmd.Stdin = strings.NewReader(input)
		return cmd.Output()
	}
	if _, err := runner(ctx, "ip", "", "link", "set", "lo", "up"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("/proc/sys/net/ipv4/conf/all/rp_filter", []byte("1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "through-linux-tun") }))
	defer server.Close()
	h := vpn.NewHandler(ctx)
	h.TCP = loopbackStream{address: server.Listener.Addr().String()}
	if useMASQUE {
		endpoints := masquetest.Start(t)
		upstream, err := masque.New(masquetest.Profile(t, endpoints), net.Dialer{Control: linuxnet.BoundDialer("lo")})
		if err != nil {
			t.Fatal(err)
		}
		defer upstream.Close()
		// Map synthetic routed destinations to loopback-only fixture services;
		// application packets still cross the real TUN and policy routes.
		h.TCP = loopbackStream{address: endpoints["tcp"], dialer: upstream}
		target, err := net.ResolveUDPAddr("udp", endpoints["udp"])
		if err != nil {
			t.Fatal(err)
		}
		h.UDP = loopbackMASQUEPackets{client: upstream, target: target}
	}
	router := &flowRouter{}
	router.replace(h)
	defer router.Close()
	dir := t.TempDir()
	resolver := filepath.Join(dir, "resolv.conf")
	os.WriteFile(resolver, []byte("nameserver 192.0.2.53\n"), 0644)
	manager := &linuxnet.Manager{Dir: dir, Resolver: resolver, Run: runner}
	platform := &linuxPlatform{manager: manager}
	link, err := platform.Open(ctx, SessionConfig{Name: "Bimeron", MTU: 1420}, router, func(string, string) {})
	if err != nil {
		t.Fatal(err)
	}
	defer link.Close()
	tr := &http.Transport{DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	for _, url := range []string{"http://203.0.113.9/", "http://[2001:db8::9]/"} {
		if useMASQUE {
			address := strings.TrimSuffix(strings.TrimPrefix(url, "http://"), "/") + ":80"
			tcp, err := net.DialTimeout("tcp", address, 3*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			_ = tcp.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := tcp.Write([]byte("through-linux-tun")); err != nil {
				tcp.Close()
				t.Fatal(err)
			}
			b := make([]byte, len("through-linux-tun"))
			_, err = io.ReadFull(tcp, b)
			tcp.Close()
			if err != nil || string(b) != "through-linux-tun" {
				t.Fatalf("TUN TCP: %q %v", b, err)
			}
			continue
		}
		response, err := client.Get(url)
		if err != nil {
			t.Fatal("TUN flow failed", url, err)
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil || string(body) != "through-linux-tun" {
			t.Fatal("invalid TUN response", string(body), err)
		}
	}
	if useMASQUE {
		udp, err := net.DialTimeout("udp", "203.0.113.9:1234", time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer udp.Close()
		_ = udp.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := udp.Write([]byte("through-masque-tun")); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 64)
		if n, err := udp.Read(b); err != nil || string(b[:n]) != "through-masque-tun" {
			t.Fatalf("TUN UDP: %q %v", b[:n], err)
		}
	}
	if err := link.Close(); err != nil {
		t.Fatal("stop failed", err)
	}
	probe, err := linuxnet.OpenTUN("Bimeron", 1420)
	if err != nil {
		t.Fatal("stopped tunnel name is still in use", err)
	}
	probe.Close()
}

type loopbackMASQUEPackets struct {
	client *masque.Client
	target net.Addr
}

func (l loopbackMASQUEPackets) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	c, err := l.client.ListenPacket(ctx)
	if err != nil {
		return nil, err
	}
	original, _ := net.ResolveUDPAddr("udp", "203.0.113.9:1234")
	return &loopbackMASQUEPacket{PacketConn: c, target: l.target, original: original}, nil
}

type loopbackMASQUEPacket struct {
	net.PacketConn
	target, original net.Addr
}

func (c *loopbackMASQUEPacket) WriteTo(b []byte, _ net.Addr) (int, error) {
	return c.PacketConn.WriteTo(b, c.target)
}
func (c *loopbackMASQUEPacket) ReadFrom(b []byte) (int, net.Addr, error) {
	n, _, err := c.PacketConn.ReadFrom(b)
	return n, c.original, err
}

func TestLinuxTUNCleanupAndImmediateReopen(t *testing.T) {
	if os.Getenv("BIMERON_NETNS_TEST") != "1" {
		t.Skip("requires unshare -n")
	}
	current, _ := os.Readlink("/proc/self/ns/net")
	host, _ := os.Readlink("/proc/1/ns/net")
	if os.Geteuid() != 0 || current == "" || current == host {
		t.Fatal("refusing to change host network namespace")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	run := func(ctx context.Context, name, input string, args ...string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, name, args...)
		cmd.Stdin = strings.NewReader(input)
		return cmd.Output()
	}
	if _, err := run(ctx, "ip", "", "link", "set", "lo", "up"); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	resolver := filepath.Join(dir, "resolv.conf")
	original := []byte("nameserver 192.0.2.53\n")
	if err := os.WriteFile(resolver, original, 0644); err != nil {
		t.Fatal(err)
	}
	manager := &linuxnet.Manager{Dir: dir, Resolver: resolver, Run: run}
	platform := &linuxPlatform{manager: manager}
	checkClean := func() {
		t.Helper()
		if _, err := net.InterfaceByName("Bimeron"); err == nil {
			t.Fatal("TUN remains after cleanup")
		}
		if err := manager.Preflight(ctx, "Bimeron"); err != nil {
			t.Fatal("network state remains after cleanup", err)
		}
		if state, err := manager.Load(); err != nil || state != nil {
			t.Fatal("recovery journal remains", state, err)
		}
		if got, err := os.ReadFile(resolver); err != nil || string(got) != string(original) {
			t.Fatal("DNS was not restored", string(got), err)
		}
		var goroutines strings.Builder
		if err := pprof.Lookup("goroutine").WriteTo(&goroutines, 2); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(goroutines.String(), "fdbased.(*endpoint).dispatchLoop") {
			t.Fatal("TUN reader goroutine remains after cleanup")
		}
	}
	open := func() (link, error) {
		router := &flowRouter{}
		return platform.Open(ctx, SessionConfig{Name: "Bimeron", MTU: 1420}, router, func(string, string) {})
	}
	for i := 0; i < 3; i++ {
		link, err := open()
		if err != nil {
			t.Fatal("immediate reopen failed", i, err)
		}
		if err := link.Close(); err != nil {
			t.Fatal("stop failed", i, err)
		}
		checkClean()
	}
	injected := false
	manager.Run = func(ctx context.Context, name, input string, args ...string) ([]byte, error) {
		if name == "ip" && strings.Join(args, " ") == "-6 rule add pref 10901 iif lo lookup "+linuxnet.Table+" protocol "+linuxnet.Protocol {
			injected = true
			return nil, errors.New("injected setup failure")
		}
		return run(ctx, name, input, args...)
	}
	if link, err := open(); err == nil {
		link.Close()
		t.Fatal("injected setup failure was ignored")
	}
	if !injected {
		t.Fatal("setup did not reach the injected failure")
	}
	manager.Run = run
	checkClean()
	link, err := open()
	if err != nil {
		t.Fatal("reopen after failed setup failed", err)
	}
	if err := link.Close(); err != nil {
		t.Fatal(err)
	}
	checkClean()
	foreign, err := linuxnet.OpenTUN("Bimeron", 1420)
	if err != nil {
		t.Fatal(err)
	}
	defer foreign.Close()
	if err := manager.Preflight(ctx, "Bimeron"); err == nil || err.Error() != "tunnel name is already in use" {
		t.Fatal("foreign TUN name was not protected", err)
	}
	if _, err := open(); err == nil {
		t.Fatal("opened a TUN owned by another caller")
	}
	if _, err := net.InterfaceByName("Bimeron"); err != nil {
		t.Fatal("foreign TUN was removed", err)
	}
}
