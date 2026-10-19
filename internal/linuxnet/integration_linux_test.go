//go:build linux

package linuxnet

import (
	"context"
	"encoding/json"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"bimeron/internal/routing"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Opt-in tests MUST run under unshare -n. They never touch the host namespace,
// /etc/resolv.conf, public servers, profiles or keys.
func requireIsolatedNetwork(t *testing.T) {
	t.Helper()
	if os.Getenv("BIMERON_NETNS_TEST") != "1" {
		t.Skip("requires isolated network namespace")
	}
	if os.Geteuid() != 0 {
		t.Fatal("namespace tests require root")
	}
	current, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	host, err := os.Readlink("/proc/1/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	if current == host {
		t.Fatal("refusing to change the host network namespace")
	}
}
func TestNativeNetworkConfigureRecover(t *testing.T) {
	requireIsolatedNetwork(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	run := func(args ...string) []byte {
		t.Helper()
		out, err := runCommand(ctx, "ip", "", args...)
		if err != nil {
			t.Fatalf("ip %v: %v", args, err)
		}
		return out
	}
	run("link", "set", "lo", "up")
	run("link", "add", "rlphysical", "type", "dummy")
	defer run("link", "del", "rlphysical")
	run("address", "add", "192.0.2.1/24", "dev", "rlphysical")
	run("link", "set", "rlphysical", "up")
	run("route", "add", "default", "dev", "rlphysical")
	d, err := OpenTUN("Bimeron", 1420)
	if err != nil {
		t.Fatal(err)
	}
	if duplicate, err := OpenTUN("Bimeron", 1420); err == nil {
		duplicate.Close()
		t.Fatal("attached to existing TUN")
	}
	defer func() {
		if d != nil {
			d.Close()
		}
	}()
	dir := t.TempDir()
	resolver := filepath.Join(dir, "resolv.conf")
	original := []byte("nameserver 192.0.2.53\n")
	if err := os.WriteFile(resolver, original, 0644); err != nil {
		t.Fatal(err)
	}
	m := &Manager{Dir: dir, Resolver: resolver, Run: runCommand}
	if nft := os.Getenv("BIMERON_NFT_BIN"); nft != "" {
		m.Run = func(ctx context.Context, name, input string, args ...string) ([]byte, error) {
			if name != "nft" {
				return runCommand(ctx, name, input, args...)
			}
			cmd := exec.CommandContext(ctx, nft, args...)
			cmd.Stdin = strings.NewReader(input)
			out, e := cmd.CombinedOutput()
			if e != nil {
				return nil, fmtError(out, e)
			}
			return out, nil
		}
	}
	guard := os.Getenv("BIMERON_NFT_BIN") != ""
	if err := m.Configure(ctx, "Bimeron", 1420, nil, true, guard); err != nil {
		t.Fatal(err)
	}
	defer m.Recover(context.Background(), false)
	out := run("-j", "route", "get", "203.0.113.9")
	if !strings.Contains(string(out), `"dev":"Bimeron"`) {
		t.Fatal("application route bypassed tunnel", string(out))
	}
	out = run("-j", "route", "get", "203.0.113.9", "mark", MarkText)
	if !strings.Contains(string(out), `"dev":"rlphysical"`) {
		t.Fatal("marked upstream recursed into tunnel", string(out))
	}
	for _, family := range []string{"-4", "-6"} {
		rs, err := m.rules(ctx, family)
		if err != nil {
			t.Fatal(err)
		}
		count := 0
		for _, r := range rs {
			if ownedRule(r) {
				count++
			}
		}
		if count != 3 {
			t.Fatal("cannot identify owned rules", rs)
		}
	}
	// Test real SO_MARK/SO_BINDTODEVICE without contacting an external server.
	c, err := (&net.Dialer{Control: BoundDialer("lo")}).DialContext(ctx, "udp4", "127.0.0.1:9")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := c.(syscall.Conn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var mark int
	var optionErr error
	raw.Control(func(fd uintptr) { mark, optionErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK) })
	c.Close()
	if optionErr != nil || mark != Mark {
		t.Fatal("SO_MARK not set", mark, optionErr)
	}
	if guard {
		d.Close()
		d = nil
		if err := m.Recover(ctx, true); err != nil {
			t.Fatal(err)
		}
		if present, err := m.guardPresent(ctx); err != nil || !present {
			t.Fatal("crash recovery released guard", err)
		}
		before := verdictPackets(t, ctx, m, "drop")
		writeUDP(t, ctx, nil, "203.0.113.9:9")
		if verdictPackets(t, ctx, m, "drop") <= before {
			t.Fatal("crashed tunnel traffic was not blocked")
		}
		before = verdictPackets(t, ctx, m, "drop")
		writeUDP(t, ctx, &net.Dialer{Control: BoundDialer("rlphysical")}, "203.0.113.9:9")
		if verdictPackets(t, ctx, m, "drop") != before {
			t.Fatal("marked core traffic blocked during recovery")
		}
		// Replacing protection must be one nftables transaction.
		d, err = OpenTUN("Bimeron", 1420)
		if err != nil {
			t.Fatal(err)
		}
		policy, err := routing.Compile(routing.Config{Default: routing.Proxy, Rules: []routing.Rule{{CIDR: "203.0.113.10/32", Action: routing.Direct}}})
		if err != nil {
			t.Fatal(err)
		}
		if err := m.Configure(ctx, "Bimeron", 1420, policy, true, true); err != nil {
			t.Fatal(err)
		}
		if err := m.Recover(ctx, true); err != nil {
			t.Fatal(err)
		}
		before = verdictPackets(t, ctx, m, "accept")
		writeUDP(t, ctx, nil, "203.0.113.10:9")
		if verdictPackets(t, ctx, m, "accept") <= before {
			t.Fatal("direct exception was blocked")
		}
	}
	if err := m.Recover(ctx, false); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(resolver)
	if string(b) != string(original) {
		t.Fatal("original DNS not restored")
	}
	for _, family := range []string{"-4", "-6"} {
		rs, _ := m.rules(ctx, family)
		for _, r := range rs {
			if ownedRule(r) {
				t.Fatal("owned route rule leaked", r)
			}
		}
	}
	if guard {
		if present, err := m.guardPresent(ctx); err != nil || present {
			t.Fatal("nft protection leaked", err)
		}
	}
}

func writeUDP(t *testing.T, ctx context.Context, d *net.Dialer, address string) {
	t.Helper()
	if d == nil {
		d = &net.Dialer{}
	}
	c, err := d.DialContext(ctx, "udp4", address)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte("isolated-route-test"))
}
func verdictPackets(t *testing.T, ctx context.Context, m *Manager, verdict string) uint64 {
	t.Helper()
	b, err := m.command(ctx, "nft", "-j", "list", "table", "inet", FirewallTable)
	if err != nil {
		t.Fatal(err)
	}
	var data struct {
		Items []struct {
			Rule *struct {
				Chain       string                       `json:"chain"`
				Expressions []map[string]json.RawMessage `json:"expr"`
			} `json:"rule"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(b, &data); err != nil {
		t.Fatal(err)
	}
	var total uint64
	for _, item := range data.Items {
		if item.Rule == nil || item.Rule.Chain != "output" {
			continue
		}
		var packets uint64
		matches := false
		for _, expr := range item.Rule.Expressions {
			if raw, ok := expr["counter"]; ok {
				var counter struct {
					Packets uint64 `json:"packets"`
				}
				json.Unmarshal(raw, &counter)
				packets = counter.Packets
			}
			if _, ok := expr[verdict]; ok {
				matches = true
			}
		}
		if matches {
			total += packets
		}
	}
	return total
}
func fmtError(out []byte, err error) error { return &commandTestError{string(out), err} }

type commandTestError struct {
	out string
	err error
}

func (e *commandTestError) Error() string { return e.err.Error() + ": " + e.out }
