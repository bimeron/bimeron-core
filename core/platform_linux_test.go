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
	"syscall"
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

// kernelHasIPv6 is false on kernels booted with ipv6.disable=1.
func kernelHasIPv6() bool {
	_, err := os.Stat("/proc/sys/net/ipv6")
	return !errors.Is(err, os.ErrNotExist)
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
	// Start from NewManager so host checks such as a missing IPv6 stack apply.
	manager := linuxnet.NewManager()
	manager.Dir, manager.Resolver, manager.Run = dir, resolver, runner
	platform := &linuxPlatform{manager: manager}
	link, err := platform.Open(ctx, SessionConfig{Name: "Bimeron", MTU: 1420}, router, func(string, string) {})
	if err != nil {
		t.Fatal(err)
	}
	defer link.Close()
	tr := &http.Transport{DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	urls := []string{"http://203.0.113.9/"}
	if kernelHasIPv6() {
		urls = append(urls, "http://[2001:db8::9]/")
	}
	for _, url := range urls {
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
	manager := linuxnet.NewManager()
	manager.Dir, manager.Resolver, manager.Run = dir, resolver, run
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
	// Fail in the last managed address family.
	family := "-6"
	if !kernelHasIPv6() {
		family = "-4"
	}
	manager.Run = func(ctx context.Context, name, input string, args ...string) ([]byte, error) {
		if name == "ip" && strings.Join(args, " ") == family+" rule add pref 10901 iif lo lookup "+linuxnet.Table+" protocol "+linuxnet.Protocol {
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

// fakeGuardSystem emulates the nft commands of the Bimeron table.
type fakeGuardSystem struct {
	present bool
	fail    bool
	calls   []string
	scripts []string
}

func (f *fakeGuardSystem) run(_ context.Context, name, input string, args ...string) ([]byte, error) {
	command := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, command)
	if name != "nft" {
		return nil, errors.New("unexpected command: " + command)
	}
	switch {
	case input != "":
		if f.fail {
			return nil, errors.New("injected nft failure")
		}
		f.scripts = append(f.scripts, input)
		f.present = true
	case command == "nft delete table inet "+linuxnet.FirewallTable:
		f.present = false
	case strings.Contains(command, "list table"):
		if f.present {
			return []byte(`{"nftables":[{"table":{"family":"inet","name":"` + linuxnet.FirewallTable + `","comment":"` + linuxnet.Owner + `"}}]}`), nil
		}
		return []byte(`{"nftables":[]}`), nil
	}
	return nil, nil
}

func TestLinuxKillSwitchBelongsToRun(t *testing.T) {
	ctx := context.Background()
	f := &fakeGuardSystem{}
	manager := &linuxnet.Manager{Dir: t.TempDir(), Resolver: filepath.Join(t.TempDir(), "resolv.conf"), Run: f.run}
	p := &linuxPlatform{killSwitch: true, name: "Bimeron", manager: manager}
	unlocked := 0
	unlock := func() { unlocked++ }
	journal := func() *linuxnet.State {
		t.Helper()
		s, err := manager.Load()
		if err != nil {
			t.Fatal(err)
		}
		return s
	}

	release, err := p.acquire(ctx, unlock)
	if err != nil {
		t.Fatal(err)
	}
	if !f.present || !p.Protected() || unlocked != 0 {
		t.Fatal("Acquire did not install run protection", f.calls)
	}
	if s := journal(); s == nil || !s.Guard || s.Name != "Bimeron" {
		t.Fatal("guard not journaled", s)
	}
	release()
	if f.present || p.Protected() || journal() != nil || unlocked != 1 {
		t.Fatal("release without RetainProtection kept protection", f.calls)
	}

	// Handover: the next run finds and atomically replaces the retained table.
	if release, err = p.acquire(ctx, unlock); err != nil {
		t.Fatal(err)
	}
	p.RetainProtection()
	release()
	if !f.present || unlocked != 2 {
		t.Fatal("RetainProtection did not keep protection", f.calls)
	}
	if s := journal(); s == nil || !s.Guard {
		t.Fatal("retained guard lost its journal", s)
	}
	if release, err = p.acquire(ctx, unlock); err != nil {
		t.Fatal(err)
	}
	if last := f.scripts[len(f.scripts)-1]; !strings.HasPrefix(last, "delete table inet "+linuxnet.FirewallTable+"\n") {
		t.Fatal("retained table was not replaced atomically", last)
	}
	release()
	if f.present || journal() != nil || unlocked != 3 {
		t.Fatal("next run release kept protection", f.calls)
	}

	// A failed install keeps the journal, unlocks, and deletes nothing.
	f.fail, f.calls = true, nil
	if _, err := p.acquire(ctx, unlock); err == nil || err.Error() != "kill_switch_arm_failed_run_recover" {
		t.Fatal("unexpected arm failure", err)
	}
	if p.Protected() || unlocked != 4 {
		t.Fatal("failed install reported protection or kept the lock")
	}
	for _, call := range f.calls {
		if strings.Contains(call, "delete table") {
			t.Fatal("failed install removed protection", f.calls)
		}
	}
	if s := journal(); s == nil || !s.Guard {
		t.Fatal("failed install must stay recoverable", s)
	}

	// Without the kill switch, leftover protection needs explicit recovery.
	off := &linuxPlatform{name: "Bimeron", manager: manager}
	if _, err := off.acquire(ctx, unlock); err == nil || err.Error() != "kill_switch_pending_run_recover" {
		t.Fatal("pending protection was not reported", err)
	}
	f.fail = false
	if err := manager.Recover(ctx, false); err != nil {
		t.Fatal(err)
	}
	f.calls = nil
	if release, err = off.acquire(ctx, unlock); err != nil {
		t.Fatal(err)
	}
	if off.Protected() || len(f.calls) != 0 {
		t.Fatal("Acquire without the kill switch touched nftables", f.calls)
	}
	release()
	if unlocked != 6 {
		t.Fatal("release did not unlock", unlocked)
	}
}

// TestLinuxTUNKillSwitchHold verifies in an isolated namespace that the kill
// switch blocks before the TUN exists and survives failed and closed sessions
// until the run releases it.
func TestLinuxTUNKillSwitchHold(t *testing.T) {
	if os.Getenv("BIMERON_NETNS_TEST") != "1" {
		t.Skip("requires unshare -n")
	}
	current, _ := os.Readlink("/proc/self/ns/net")
	host, _ := os.Readlink("/proc/1/ns/net")
	if os.Geteuid() != 0 || current == "" || current == host {
		t.Fatal("refusing to change host network namespace")
	}
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("requires nftables")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	run := func(ctx context.Context, name, input string, args ...string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, name, args...)
		cmd.Stdin = strings.NewReader(input)
		return cmd.Output()
	}
	for _, args := range [][]string{
		{"link", "set", "lo", "up"},
		{"link", "add", "rlphysical", "type", "dummy"},
		{"address", "add", "192.0.2.1/24", "dev", "rlphysical"},
		{"link", "set", "rlphysical", "up"},
		{"route", "add", "default", "dev", "rlphysical"},
	} {
		if _, err := run(ctx, "ip", "", args...); err != nil {
			t.Fatal("ip", args, err)
		}
	}
	defer run(context.Background(), "ip", "", "link", "del", "rlphysical")
	dir := t.TempDir()
	resolver := filepath.Join(dir, "resolv.conf")
	if err := os.WriteFile(resolver, []byte("nameserver 192.0.2.53\n"), 0644); err != nil {
		t.Fatal(err)
	}
	manager := linuxnet.NewManager()
	manager.Dir, manager.Resolver, manager.Run = dir, resolver, run
	defer manager.Recover(context.Background(), false)
	p := &linuxPlatform{killSwitch: true, name: "Bimeron", manager: manager}
	// nftables drops in OUTPUT make an unmarked UDP send fail with EPERM.
	send := func(d *net.Dialer) error {
		t.Helper()
		c, err := d.DialContext(ctx, "udp4", "203.0.113.9:9")
		if err != nil {
			return err
		}
		defer c.Close()
		_, err = c.Write([]byte("kill-switch-hold"))
		return err
	}
	blocked := func(stage string) {
		t.Helper()
		if _, err := run(ctx, "nft", "", "list", "table", "inet", linuxnet.FirewallTable); err != nil {
			t.Fatal(stage, "kill switch table missing", err)
		}
		if err := send(&net.Dialer{}); !errors.Is(err, syscall.EPERM) {
			t.Fatal(stage, "unmarked traffic was not blocked", err)
		}
		if err := send(&net.Dialer{Control: linuxnet.BoundDialer("rlphysical")}); err != nil {
			t.Fatal(stage, "marked core traffic was blocked", err)
		}
	}
	open := func() (link, error) {
		return p.Open(ctx, SessionConfig{Name: "Bimeron", MTU: 1420, KillSwitch: true}, &flowRouter{}, func(string, string) {})
	}
	// A closed session removes its TUN; only the run-scoped guard remains.
	tunGone := func(stage string) {
		t.Helper()
		if _, err := net.InterfaceByName("Bimeron"); err == nil {
			t.Fatal(stage, "TUN interface still exists")
		}
	}

	release, err := p.acquire(ctx, func() {})
	if err != nil {
		t.Fatal(err)
	}
	blocked("before the tunnel exists:")
	manager.Run = func(ctx context.Context, name, input string, args ...string) ([]byte, error) {
		if name == "ip" && strings.Join(args, " ") == "-4 rule add pref "+linuxnet.TunnelPriority+" iif lo lookup "+linuxnet.Table+" protocol "+linuxnet.Protocol {
			return nil, errors.New("injected setup failure")
		}
		return run(ctx, name, input, args...)
	}
	if l, err := open(); err == nil {
		l.Close()
		t.Fatal("injected setup failure was ignored")
	}
	manager.Run = run
	blocked("after a failed session:")
	tunGone("after a failed session:")
	for i := 0; i < 2; i++ {
		l, err := open()
		if err != nil {
			t.Fatal(err)
		}
		if err := l.Close(); err != nil {
			t.Fatal(err)
		}
		blocked("after a closed session:")
		tunGone("after a closed session:")
		if s, err := manager.Load(); err != nil || s == nil || !s.Guard || s.Routing || s.DNSMethod != "" {
			t.Fatal("journal must keep only the guard", s, err)
		}
	}
	p.RetainProtection()
	release()
	blocked("after a retained release:")
	if release, err = p.acquire(ctx, func() {}); err != nil {
		t.Fatal(err)
	}
	release()
	if _, err := run(ctx, "nft", "", "list", "table", "inet", linuxnet.FirewallTable); err == nil {
		t.Fatal("release kept the kill switch table")
	}
	if s, err := manager.Load(); err != nil || s != nil {
		t.Fatal("recovery journal remains", s, err)
	}
	if err := send(&net.Dialer{}); err != nil {
		t.Fatal("traffic still blocked after release", err)
	}
	tunGone("after stop:")
}
