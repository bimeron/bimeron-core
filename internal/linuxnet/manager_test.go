package linuxnet

import (
	"bimeron/internal/routing"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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

func TestResolverFileSingleAttemptTimeout(t *testing.T) {
	for count, seconds := range map[int]int{1: 5, 2: 9, 3: 13, 4: 17} {
		m, _, _ := testManager(t)
		if err := m.Configure(context.Background(), "Bimeron", 1420, count, nil, true, false); err != nil {
			t.Fatal(err)
		}
		contents, err := os.ReadFile(m.Resolver)
		if err != nil {
			t.Fatal(err)
		}
		want := fmt.Sprintf("options timeout:%d attempts:2", seconds)
		if !strings.Contains(string(contents), "\n"+want+"\n") {
			t.Errorf("%d servers: expected %q in %q", count, want, contents)
		}
	}
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
	if err := m.Configure(context.Background(), "Bimeron", 1420, 2, p, true, false); err != nil {
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
	if err := m.Configure(ctx, "Bimeron", 1420, 2, nil, true, true); err != nil {
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
	if err := m.Configure(context.Background(), "Bimeron", 1420, 2, nil, true, true); err == nil {
		t.Fatal("expected setup failure")
	}
	b, _ := os.ReadFile(m.Resolver)
	if string(b) != string(original) || f.guard || len(f.rules["-4"]) != 0 || len(f.rules["-6"]) != 0 {
		t.Fatal("partial setup not rolled back", f.calls)
	}
}
func TestRollbackKeepsGuardFromCrashedSession(t *testing.T) {
	m, f, original := testManager(t)
	ctx := context.Background()
	if err := m.Configure(ctx, "Bimeron", 1420, 2, nil, true, true); err != nil {
		t.Fatal(err)
	}
	// Crash, then the next session's Acquire retains the kill switch.
	if err := m.Recover(ctx, true); err != nil {
		t.Fatal(err)
	}
	f.calls = nil
	f.fail = "-6 rule add pref 10901"
	if err := m.Configure(ctx, "Bimeron", 1420, 2, nil, true, true); err == nil {
		t.Fatal("expected setup failure")
	}
	for _, call := range f.calls {
		if strings.Contains(call, "delete table inet bimeron_core") {
			t.Fatal("rollback removed retained protection", f.calls)
		}
	}
	b, _ := os.ReadFile(m.Resolver)
	if string(b) != string(original) || !f.guard || len(f.rules["-4"]) != 0 || len(f.rules["-6"]) != 0 {
		t.Fatal("rollback lost protection or left routing", f.calls)
	}
	if s, err := m.Load(); err != nil || s == nil || !s.Guard || s.Routing {
		t.Fatal("journal must keep only the guard", s, err)
	}
}

// guardScripts records nft scripts and the journal each one was applied over.
func guardScripts(t *testing.T, m *Manager, f *fakeSystem) (*[]string, *[]*State) {
	t.Helper()
	var scripts []string
	var journals []*State
	m.Run = func(ctx context.Context, name, input string, args ...string) ([]byte, error) {
		if name == "nft" && input != "" {
			scripts = append(scripts, input)
			s, err := m.Load()
			if err != nil {
				t.Fatal(err)
			}
			journals = append(journals, s)
		}
		return f.run(ctx, name, input, args...)
	}
	return &scripts, &journals
}

func TestGuardBeforeTunnelIsJournaledAndHeldAcrossSessions(t *testing.T) {
	m, f, original := testManager(t)
	scripts, journals := guardScripts(t, m, f)
	ctx := context.Background()
	p, err := routing.Compile(routing.Config{Default: routing.Proxy, Rules: []routing.Rule{{CIDR: "192.168.1.0/24", Action: routing.Direct}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Guard(ctx, "Bimeron", p, true); err != nil {
		t.Fatal(err)
	}
	if !f.guard || len(*scripts) != 1 {
		t.Fatal("guard not installed", f.calls)
	}
	if s := (*journals)[0]; s == nil || !s.Guard || s.Name != "Bimeron" || s.Routing || s.DNSMethod != "" {
		t.Fatal("journal must record the guard before nft runs", s)
	}
	want, err := Firewall("Bimeron", p, true, false)
	if err != nil || (*scripts)[0] != want {
		t.Fatal("guard must use exactly the Firewall exceptions", (*scripts)[0], err)
	}
	for _, call := range f.calls {
		if strings.HasPrefix(call, "ip ") {
			t.Fatal("guard touched routing before the tunnel exists", call)
		}
	}
	// Re-arming replaces the owned table atomically, without a gap.
	if err := m.Guard(ctx, "Bimeron", p, true); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix((*scripts)[1], "delete table inet "+FirewallTable+"\n") {
		t.Fatal("re-arming did not replace the table", (*scripts)[1])
	}
	// Session setups and session cleanups keep the run's guard.
	for i := 0; i < 2; i++ {
		if err := m.Configure(ctx, "Bimeron", 1420, 2, p, true, true); err != nil {
			t.Fatal(err)
		}
		if last := (*scripts)[len(*scripts)-1]; !strings.HasPrefix(last, "delete table inet "+FirewallTable+"\n") {
			t.Fatal("Configure did not replace the early guard", last)
		}
		if err := m.Recover(ctx, true); err != nil {
			t.Fatal(err)
		}
		b, _ := os.ReadFile(m.Resolver)
		if string(b) != string(original) || !f.guard || len(f.rules["-4"]) != 0 || len(f.routes["-4"]) != 0 {
			t.Fatal("session cleanup lost the guard or left routing", f.calls)
		}
		if s, err := m.Load(); err != nil || s == nil || !s.Guard || s.Routing || s.DNSMethod != "" {
			t.Fatal("journal must keep only the guard", s, err)
		}
	}
	// Run release.
	if err := m.Recover(ctx, false); err != nil {
		t.Fatal(err)
	}
	if f.guard {
		t.Fatal("release kept the guard")
	}
	if s, err := m.Load(); err != nil || s != nil {
		t.Fatal("journal was not cleared", s, err)
	}
}

func TestConfigureRollbackKeepsEarlyGuard(t *testing.T) {
	m, f, original := testManager(t)
	ctx := context.Background()
	if err := m.Guard(ctx, "Bimeron", nil, true); err != nil {
		t.Fatal(err)
	}
	f.calls = nil
	f.fail = "-6 rule add pref 10901"
	if err := m.Configure(ctx, "Bimeron", 1420, 2, nil, true, true); err == nil {
		t.Fatal("expected setup failure")
	}
	for _, call := range f.calls {
		if strings.Contains(call, "delete table inet bimeron_core") {
			t.Fatal("rollback removed the early guard", f.calls)
		}
	}
	b, _ := os.ReadFile(m.Resolver)
	if string(b) != string(original) || !f.guard || len(f.rules["-4"]) != 0 || len(f.rules["-6"]) != 0 {
		t.Fatal("rollback lost protection or left routing", f.calls)
	}
	if s, err := m.Load(); err != nil || s == nil || !s.Guard || s.Routing {
		t.Fatal("journal must keep only the guard", s, err)
	}
}

func TestGuardFailureKeepsJournal(t *testing.T) {
	m, f, _ := testManager(t)
	f.fail = "nft -f -"
	if err := m.Guard(context.Background(), "Bimeron", nil, true); err == nil {
		t.Fatal("expected nft failure")
	}
	if s, err := m.Load(); err != nil || s == nil || !s.Guard || s.Name != "Bimeron" {
		t.Fatal("failed install must stay recoverable", s, err)
	}
	for _, call := range f.calls {
		if strings.Contains(call, "delete table") {
			t.Fatal("failed install removed protection", f.calls)
		}
	}
}

func TestGuardRefusesUnrecoveredSession(t *testing.T) {
	m, f, _ := testManager(t)
	ctx := context.Background()
	if err := m.Configure(ctx, "Bimeron", 1420, 2, nil, true, false); err != nil {
		t.Fatal(err)
	}
	f.calls = nil
	if err := m.Guard(ctx, "Other", nil, true); err == nil {
		t.Fatal("guard overwrote an unrecovered journal")
	}
	if f.guard || len(f.calls) != 0 {
		t.Fatal("guard ran over an unrecovered session", f.calls)
	}
	if s, err := m.Load(); err != nil || s == nil || s.Name != "Bimeron" || !s.Routing {
		t.Fatal("journal changed", s, err)
	}
}

func TestDisabledIPv6DirectPrefixesStayInTunnel(t *testing.T) {
	p, err := routing.Compile(routing.Config{Default: routing.Proxy, Rules: []routing.Rule{{CIDR: "2001:db8::/32", Action: routing.Direct}, {CIDR: "192.168.1.0/24", Action: routing.Direct}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, disable := range []bool{true, false} {
		m, f, _ := testManager(t)
		if err := m.Configure(context.Background(), "Bimeron", 1420, 2, p, disable, false); err != nil {
			t.Fatal(err)
		}
		throw6 := false
		for _, call := range f.calls {
			if strings.Contains(call, "-6 route add throw 2001:db8::/32") {
				throw6 = true
			}
		}
		if throw6 == disable || len(f.routes["-4"]) != 2 {
			t.Fatal("unexpected IPv6 bypass", disable, f.calls)
		}
	}
}
func TestKernelWithoutIPv6SkipsIPv6Commands(t *testing.T) {
	m, f, original := testManager(t)
	m.NoIPv6 = func() bool { return true }
	ctx := context.Background()
	p, err := routing.Compile(routing.Config{Default: routing.Proxy, Rules: []routing.Rule{{CIDR: "2001:db8::/32", Action: routing.Direct}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Preflight(ctx, "Bimeron2"); err != nil {
		t.Fatal(err)
	}
	if err := m.Configure(ctx, "Bimeron", 1420, 2, p, false, true); err != nil {
		t.Fatal(err)
	}
	if !f.guard || len(f.rules["-4"]) != 3 {
		t.Fatal("IPv4 protection not configured", f.calls)
	}
	if err := m.Recover(ctx, false); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(m.Resolver)
	if string(b) != string(original) || f.guard || len(f.rules["-4"]) != 0 {
		t.Fatal("recovery incomplete", f.calls)
	}
	for _, call := range f.calls {
		if strings.HasPrefix(call, "ip -6 ") {
			t.Fatal("IPv6 command on a kernel without IPv6", call)
		}
	}
}
func TestExternalDNSChangeKeepsProtection(t *testing.T) {
	m, f, _ := testManager(t)
	ctx := context.Background()
	if err := m.Configure(ctx, "Bimeron", 1420, 2, nil, true, true); err != nil {
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

func TestUsesResolvedStub(t *testing.T) {
	for input, want := range map[string]bool{
		"  nameserver\t127.0.0.53 # stub":                                     true,
		"# old settings\nnameserver   127.0.0.54":                             true,
		"# nameserver 127.0.0.53\n;nameserver 127.0.0.54\nnameserver 1.1.1.1": false,
		"nameserver 127.0.0.530":                                              false,
		"search nameserver 127.0.0.54":                                        false,
	} {
		if got := usesResolvedStub(input); got != want {
			t.Errorf("usesResolvedStub(%q) = %t, want %t", input, got, want)
		}
	}
}

func TestResolvedRevertDoesNotOverwriteResolverFile(t *testing.T) {
	m, f, _ := testManager(t)
	stub := []byte("nameserver 127.0.0.53\n")
	os.WriteFile(m.Resolver, stub, 0644)
	if err := m.Configure(context.Background(), "Bimeron", 1420, 2, nil, false, false); err != nil {
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

func TestResolvedDNSGuardLifecycle(t *testing.T) {
	ctx := context.Background()
	m, f, _ := testManager(t)
	if err := os.WriteFile(m.Resolver, []byte("nameserver 127.0.0.53\n"), 0644); err != nil {
		t.Fatal(err)
	}
	scripts, journals := guardScripts(t, m, f)
	if err := m.Configure(ctx, "Bimeron", 1420, 2, nil, false, false); err != nil {
		t.Fatal(err)
	}
	if len(*scripts) != 1 {
		t.Fatalf("expected one nft transaction, got %v", *scripts)
	}
	for _, fragment := range []string{
		"create table inet bimeron_core",
		"policy accept",
		`oifname != "lo" oifname != "Bimeron" meta mark != 0x524c meta l4proto { tcp, udp } th dport { 53, 853 } drop`,
	} {
		if !strings.Contains((*scripts)[0], fragment) {
			t.Fatalf("missing %q in DNS guard", fragment)
		}
	}
	if s := (*journals)[0]; s == nil || s.Version != 2 || !s.DNSGuard || s.Guard || s.DNSMethod != "" {
		t.Fatalf("unexpected journal before DNS guard installation: %+v", s)
	}
	f.fail = "resolvectl revert"
	if err := m.Recover(ctx, true); err == nil || !f.guard {
		t.Fatal("incomplete recovery must keep DNS protection")
	}
	f.fail = ""
	if err := m.Recover(ctx, true); err != nil || f.guard {
		t.Fatal("recovery must release the session DNS guard even when preserving a kill switch", err)
	}
	if s, err := m.Load(); err != nil || s != nil {
		t.Fatal("journal remained after recovery", s, err)
	}
}

func TestResolvedDNSGuardInstallFailureRollsBack(t *testing.T) {
	m, f, _ := testManager(t)
	if err := os.WriteFile(m.Resolver, []byte("nameserver 127.0.0.53\n"), 0644); err != nil {
		t.Fatal(err)
	}
	f.fail = "nft -f -"
	if err := m.Configure(context.Background(), "Bimeron", 1420, 2, nil, false, false); err == nil {
		t.Fatal("setup accepted an unprotected resolver")
	}
	if strings.Contains(strings.Join(f.calls, "\n"), "resolvectl ") {
		t.Fatal("resolver configured before guard installation")
	}
	if s, err := m.Load(); s != nil || err != nil {
		t.Fatal("incomplete rollback", s, err)
	}
}
