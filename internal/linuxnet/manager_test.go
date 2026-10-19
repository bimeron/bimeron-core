package linuxnet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"bimeron/internal/routing"
	"strings"
	"testing"
)

type fakeSystem struct {
	calls  []string
	rules  map[string][]rule
	routes map[string][]route
	guard  bool
	fail   string
}

func newFake() *fakeSystem {
	return &fakeSystem{rules: map[string][]rule{}, routes: map[string][]route{}}
}
func (f *fakeSystem) run(_ context.Context, name, input string, args ...string) ([]byte, error) {
	command := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, command)
	if f.fail != "" && strings.Contains(command, f.fail) {
		return nil, errors.New("injected failure")
	}
	raw := func(v any) ([]byte, error) { return json.Marshal(v) }
	if name == "nft" {
		if strings.Contains(command, "list table") {
			if f.guard {
				if !strings.Contains(command, "-j") {
					return []byte(`table inet bimeron_core { comment "Bimeron Core"; }`), nil
				}
				return []byte(`{"nftables":[{"table":{"family":"inet","name":"bimeron_core","comment":"Bimeron Core"}}]}`), nil
			}
			return []byte(`{"nftables":[]}`), nil
		}
		if input != "" {
			f.guard = true
		}
		if strings.Contains(command, "delete table") {
			f.guard = false
		}
		return nil, nil
	}
	if strings.Contains(command, "link show") {
		return []byte(`[{"ifindex":42,"ifname": "Bimeron"}]`), nil
	}
	family := "-4"
	if len(args) > 0 && args[0] == "-6" {
		family = "-6"
	}
	if strings.Contains(command, "rule show") {
		return raw(f.rules[family])
	}
	if strings.Contains(command, "route show") {
		return raw(f.routes[family])
	}
	if strings.Contains(command, "rule add pref 10900") {
		f.rules[family] = append(f.rules[family], rule{Priority: 10900, Table: json.RawMessage(`"main"`), Mark: json.RawMessage(`"0x524c"`), Protocol: json.RawMessage(Protocol)})
	}
	if strings.Contains(command, "rule add pref 10901") {
		f.rules[family] = append(f.rules[family], rule{Priority: 10901, Table: json.RawMessage(Table), Protocol: json.RawMessage(Protocol), Input: "lo"})
	}
	if strings.Contains(command, "rule add pref 10902") {
		f.rules[family] = append(f.rules[family], rule{Priority: 10902, Table: json.RawMessage(Table), Protocol: json.RawMessage(Protocol), Input: "Bimeron"})
	}
	if strings.Contains(command, "rule del") {
		var remaining []rule
		for _, r := range f.rules[family] {
			if !ownedRule(r) || !strings.Contains(command, fmt.Sprint(r.Priority)) {
				remaining = append(remaining, r)
			}
		}
		f.rules[family] = remaining
	}
	if strings.Contains(command, "route add default") {
		f.routes[family] = append(f.routes[family], route{Destination: "default", Device: "Bimeron", Table: json.RawMessage(Table), Protocol: json.RawMessage(Protocol)})
	}
	if strings.Contains(command, "route add throw") {
		parts := strings.Fields(command)
		f.routes[family] = append(f.routes[family], route{Destination: parts[5], Type: "throw", Table: json.RawMessage(Table), Protocol: json.RawMessage(Protocol)})
	}
	if strings.Contains(command, "route del") {
		f.routes[family] = nil
	}
	return nil, nil
}

func TestGuardOwnershipFallbackForOldNftables(t *testing.T) {
	m, f, _ := testManager(t)
	f.guard = true
	m.Run = func(ctx context.Context, name, input string, args ...string) ([]byte, error) {
		if name == "nft" && strings.Join(args, " ") == "-j list table inet bimeron_core" {
			return []byte(`{"nftables":[{"table":{"family":"inet","name":"bimeron_core"}}]}`), nil
		}
		return f.run(ctx, name, input, args...)
	}
	if present, err := m.guardPresent(context.Background()); err != nil || !present {
		t.Fatal("old nftables comment fallback failed", present, err)
	}
}

func TestDirectCIDRBypassesTunnelAndIsRecovered(t *testing.T) {
	m, f, _ := testManager(t)
	p, err := routing.Compile(routing.Config{Default: routing.Proxy, Rules: []routing.Rule{{CIDR: "192.168.1.0/24", Action: routing.Direct}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Configure(context.Background(), "Bimeron", 1420, p, true, false); err != nil {
		t.Fatal(err)
	}
	if len(f.routes["-4"]) != 2 || f.routes["-4"][0].Type != "throw" || f.routes["-4"][0].Destination != "192.168.1.0/24" {
		t.Fatal("direct route did not bypass tunnel", f.routes["-4"])
	}
	if err := m.Recover(context.Background(), false); err != nil || len(f.routes["-4"]) != 0 {
		t.Fatal("direct route was not recovered", err, f.routes["-4"])
	}
}
func testManager(t *testing.T) (*Manager, *fakeSystem, []byte) {
	t.Helper()
	dir := t.TempDir()
	resolver := filepath.Join(dir, "resolv.conf")
	original := []byte("nameserver 9.9.9.9\nsearch example.test\n")
	if err := os.WriteFile(resolver, original, 0644); err != nil {
		t.Fatal(err)
	}
	f := newFake()
	return &Manager{Dir: dir, Resolver: resolver, Run: f.run}, f, original
}
func TestConfigureRecoverAndBootstrapDNS(t *testing.T) {
	m, f, original := testManager(t)
	ctx := context.Background()
	if err := m.Configure(ctx, "Bimeron", 1420, nil, true, true); err != nil {
		t.Fatal(err)
	}
	if !f.guard {
		t.Fatal("guard not installed")
	}
	if got := m.BootstrapDNS(ctx, "eth0"); len(got) != 1 || got[0] != "9.9.9.9" {
		t.Fatal("bootstrap lost physical DNS", got)
	}
	// Simulate a crashed process, then recover routing/DNS without releasing protection.
	if err := m.Recover(ctx, true); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(m.Resolver)
	if string(b) != string(original) || !f.guard {
		t.Fatal("crash recovery removed protection or lost original DNS")
	}
	if err := m.Recover(ctx, false); err != nil {
		t.Fatal(err)
	}
	if f.guard {
		t.Fatal("guard retained after explicit recover")
	}
	if state, err := m.Load(); err != nil || state != nil {
		t.Fatal("journal was not cleared", state, err)
	}
}
func TestRollbackAfterPartialSetup(t *testing.T) {
	m, f, original := testManager(t)
	f.fail = "-6 rule add pref 10901"
	if err := m.Configure(context.Background(), "Bimeron", 1420, nil, true, true); err == nil {
		t.Fatal("expected setup failure")
	}
	b, _ := os.ReadFile(m.Resolver)
	if string(b) != string(original) || f.guard || len(f.rules["-4"]) != 0 || len(f.rules["-6"]) != 0 {
		t.Fatal("partial setup not rolled back", f.calls)
	}
}
func TestExternalDNSChangeKeepsProtection(t *testing.T) {
	m, f, _ := testManager(t)
	ctx := context.Background()
	if err := m.Configure(ctx, "Bimeron", 1420, nil, true, true); err != nil {
		t.Fatal(err)
	}
	external := []byte("nameserver 8.8.8.8\n")
	os.WriteFile(m.Resolver, external, 0644)
	if err := m.Recover(ctx, false); err == nil {
		t.Fatal("expected external DNS conflict")
	}
	b, _ := os.ReadFile(m.Resolver)
	if string(b) != string(external) || !f.guard {
		t.Fatal("overwrote external DNS or removed guard")
	}
	if err := m.KeepCurrentDNS(); err != nil {
		t.Fatal(err)
	}
	if err := m.Recover(ctx, false); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(m.Resolver)
	if string(b) != string(external) || f.guard {
		t.Fatal("explicit recovery did not preserve external DNS")
	}
}
func TestForeignRoutingRuleIsNotRemoved(t *testing.T) {
	m, f, _ := testManager(t)
	ctx := context.Background()
	s := &State{Version: 1, Name: "Bimeron", Routing: true}
	if err := m.save(s); err != nil {
		t.Fatal(err)
	}
	foreign := rule{Priority: 10901, Table: json.RawMessage(`123`), Protocol: json.RawMessage(Protocol)}
	f.rules["-4"] = []rule{foreign}
	if err := m.Recover(ctx, false); err != nil {
		t.Fatal(err)
	}
	if len(f.rules["-4"]) != 1 {
		t.Fatal("removed foreign routing rule")
	}
}
func TestFirewallPreservesFirstMatchAndBlocksExistingFlows(t *testing.T) {
	p, err := routing.Compile(routing.Config{Default: routing.Direct, Rules: []routing.Rule{{CIDR: "8.8.8.8/32", Action: routing.Proxy}, {CIDR: "8.8.8.0/24", Action: routing.Direct}}})
	if err != nil {
		t.Fatal(err)
	}
	script, err := Firewall("Bimeron", p, true, true)
	if err != nil {
		t.Fatal(err)
	}
	first := strings.Index(script, "ip daddr 8.8.8.8/32 counter drop")
	second := strings.Index(script, "ip daddr 8.8.8.0/24 counter accept")
	if first < 0 || second <= first || !strings.Contains(script, "ip6 daddr ::/0 counter drop") || strings.Contains(script, "ct state established") || strings.Contains(script, "skuid") {
		t.Fatal(script)
	}
	if _, err := Firewall("bad;name", nil, false, false); err == nil {
		t.Fatal("unsafe interface accepted")
	}
}
func TestReservedRulesFailPreflight(t *testing.T) {
	m, f, _ := testManager(t)
	f.rules["-4"] = []rule{{Priority: 10900}}
	if m.Preflight(context.Background(), "OtherTun") == nil {
		t.Fatal("conflict accepted")
	}
	for _, call := range f.calls {
		if strings.Contains(call, " add ") {
			t.Fatal("preflight mutated network")
		}
	}
}

func TestResolvedRevertDoesNotOverwriteResolverFile(t *testing.T) {
	m, f, _ := testManager(t)
	stub := []byte("nameserver 127.0.0.53\n")
	os.WriteFile(m.Resolver, stub, 0644)
	if err := m.Configure(context.Background(), "Bimeron", 1420, nil, false, false); err != nil {
		t.Fatal(err)
	}
	if err := m.Recover(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(m.Resolver)
	if string(b) != string(stub) {
		t.Fatal("rewrote resolved stub")
	}
	found := false
	for _, call := range f.calls {
		if call == "resolvectl revert Bimeron" {
			found = true
		}
	}
	if !found {
		t.Fatal("resolved settings not reverted")
	}
}
func TestResolvedDoesNotRevertReusedInterfaceName(t *testing.T) {
	m, f, _ := testManager(t)
	ctx := context.Background()
	if err := m.save(&State{Version: 1, Name: "Bimeron", Index: 41, DNSMethod: "resolved"}); err != nil {
		t.Fatal(err)
	}
	if err := m.Recover(ctx, false); err != nil {
		t.Fatal(err)
	}
	for _, call := range f.calls {
		if strings.Contains(call, "resolvectl revert") {
			t.Fatal("reverted DNS on a foreign interface")
		}
	}
}
