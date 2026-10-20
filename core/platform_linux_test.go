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
	"bimeron/internal/vpn"
	"golang.getoutline.org/sdk/transport"
)

type loopbackStream struct{ address string }

func (d loopbackStream) DialStream(ctx context.Context, _ string) (transport.StreamConn, error) {
	return (&transport.TCPDialer{}).DialStream(ctx, d.address)
}

func TestLinuxTUNHTTP(t *testing.T) {
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
	if err := link.Close(); err != nil {
		t.Fatal("stop failed", err)
	}
	probe, err := linuxnet.OpenTUN("Bimeron", 1420)
	if err != nil {
		t.Fatal("stopped tunnel name is still in use", err)
	}
	probe.Close()
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
