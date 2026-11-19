//go:build windows

package killswitch

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"reflect"
	"testing"

	"github.com/tailscale/wf"
	"golang.org/x/sys/windows"
)

// This fake never calls Windows; real WFP installation is a manual test.
// Its persistent state (rules, provider, sublayer) outlives the session, which
// closed tracks; reopen models a new process opening a session to the same state.
type fakeAPI struct {
	rules                 []*wf.Rule
	adds, failAt          int
	deleteErr             bool
	hasProvider, hasLayer bool
	closed                bool
}

func (f *fakeAPI) Transaction(fn func() error) error {
	old, hadProvider, hadLayer := append([]*wf.Rule(nil), f.rules...), f.hasProvider, f.hasLayer
	if err := fn(); err != nil {
		f.rules, f.hasProvider, f.hasLayer = old, hadProvider, hadLayer
		return err
	}
	return nil
}
func (f *fakeAPI) AddProvider(*wf.Provider) error { f.hasProvider = true; return nil }
func (f *fakeAPI) AddSublayer(*wf.Sublayer) error { f.hasLayer = true; return nil }
func (f *fakeAPI) AddRule(r *wf.Rule) error {
	f.adds++
	if f.adds == f.failAt {
		return errors.New("failed add")
	}
	f.rules = append(f.rules, r)
	return nil
}
func (f *fakeAPI) Rules() ([]*wf.Rule, error) { return append([]*wf.Rule(nil), f.rules...), nil }
func (f *fakeAPI) DeleteRule(id wf.RuleID) error {
	if f.deleteErr {
		return errors.New("failed delete")
	}
	for i, r := range f.rules {
		if r.ID == id {
			f.rules = append(f.rules[:i], f.rules[i+1:]...)
			break
		}
	}
	return nil
}
func (f *fakeAPI) DeleteSublayer(wf.SublayerID) error { f.hasLayer = false; return nil }
func (f *fakeAPI) DeleteProvider(wf.ProviderID) error { f.hasProvider = false; return nil }
func (f *fakeAPI) Close() error {
	if f.closed {
		return errors.New("session already closed")
	}
	f.closed = true
	return nil
}
func (f *fakeAPI) reopen() *fakeAPI { f.closed = false; return f }
func priorRule() *wf.Rule {
	return &wf.Rule{ID: wf.RuleID(windows.GUID{Data1: 9}), Provider: provider, Sublayer: sublayer, Action: wf.ActionBlock, Persistent: true}
}
func TestPersistentFiltersAndOwnedCleanup(t *testing.T) {
	other := &wf.Rule{ID: wf.RuleID(windows.GUID{Data1: 7})}
	f := &fakeAPI{rules: []*wf.Rule{priorRule(), other}}
	plan, _ := Plan(nil, false)
	var g *Guard
	err := f.Transaction(func() error { var e error; g, e = arm(f, 42, "test-app", plan); return e })
	if err != nil {
		t.Fatal(err)
	}
	if len(f.rules) < 10 {
		t.Fatal("missing protection")
	}
	denies := map[wf.LayerID]bool{}
	for _, r := range f.rules {
		if r == other {
			continue
		}
		if !r.Persistent || r.Provider != provider || r.Sublayer != sublayer {
			t.Fatal("not persistent/owned")
		}
		if r.Action == wf.ActionBlock {
			denies[r.Layer] = true
		}
	}
	for _, l := range []wf.LayerID{wf.LayerALEAuthConnectV4, wf.LayerALEAuthConnectV6, wf.LayerALEAuthRecvAcceptV4, wf.LayerALEAuthRecvAcceptV6} {
		if !denies[l] {
			t.Fatal("unprotected layer", l)
		}
	}
	if err = g.Close(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f.rules, []*wf.Rule{other}) {
		t.Fatal("removed unrelated filters")
	}
}
func TestAtomicInstallAndRemoveFailureKeepProtection(t *testing.T) {
	old := priorRule()
	plan, _ := Plan(nil, false)
	for _, failAt := range []int{1, 5, 15} {
		f := &fakeAPI{rules: []*wf.Rule{old}, failAt: failAt}
		err := f.Transaction(func() error { _, e := arm(f, 42, "test-app", plan); return e })
		if err == nil || !reflect.DeepEqual(f.rules, []*wf.Rule{old}) {
			t.Fatal("failed update lost old protection", failAt)
		}
	}
	f := &fakeAPI{rules: []*wf.Rule{old}, deleteErr: true}
	if err := (&Guard{s: f}).Close(); err == nil || len(f.rules) != 1 {
		t.Fatal("failed cleanup did not keep protection")
	}
}

// assertCoreExceptions checks every core executable exception. Weights read
// back from WFP are effective weights, so live checks skip them.
func assertCoreExceptions(t *testing.T, rules []*wf.Rule, checkWeight bool) {
	t.Helper()
	layers := map[wf.LayerID]bool{}
	for _, r := range rules {
		var app, user bool
		for _, c := range r.Conditions {
			switch c.Field {
			case wf.FieldALEAppID:
				app = true
			case wf.FieldALEUserID:
				sd, ok := c.Value.(*windows.SECURITY_DESCRIPTOR)
				if !ok || c.Op != wf.MatchTypeEqual || sd.String() != coreTokenSDDL {
					t.Fatalf("core exception has unexpected token condition %v %v", c.Op, c.Value)
				}
				user = true
			}
		}
		if app != user {
			t.Fatalf("core exception on %v is not bound to an administrative token", r.Layer)
		}
		if app {
			if r.Action != wf.ActionPermit || (checkWeight && r.Weight != ^uint64(0)) || layers[r.Layer] {
				t.Fatalf("unexpected core exception on %v", r.Layer)
			}
			layers[r.Layer] = true
		}
	}
	for _, l := range []wf.LayerID{wf.LayerALEAuthConnectV4, wf.LayerALEAuthConnectV6, wf.LayerALEAuthRecvAcceptV4, wf.LayerALEAuthRecvAcceptV6} {
		if !layers[l] {
			t.Fatal("missing core exception", l)
		}
	}
}

func TestCoreExceptionRequiresAdministrativeToken(t *testing.T) {
	// An exception from an older release matches the image path only. It must
	// be replaced by the token-bound rule set on the next arm.
	legacy := &wf.Rule{ID: wf.RuleID(windows.GUID{Data1: 11}), Provider: provider, Sublayer: sublayer, Layer: wf.LayerALEAuthConnectV4, Weight: ^uint64(0), Action: wf.ActionPermit, Persistent: true,
		Conditions: []*wf.Match{{Field: wf.FieldALEAppID, Op: wf.MatchTypeEqual, Value: "test-app"}}}
	f := &fakeAPI{rules: []*wf.Rule{legacy}}
	plan, _ := Plan(nil, false)
	if err := f.Transaction(func() error { _, e := arm(f, 42, "test-app", plan); return e }); err != nil {
		t.Fatal(err)
	}
	for _, r := range f.rules {
		if r == legacy {
			t.Fatal("legacy exception was not replaced")
		}
	}
	assertCoreExceptions(t, f.rules, true)
}

// signatures describes rules independently of their generated IDs.
func signatures(rules []*wf.Rule, skipInterface bool) []string {
	var result []string
	for _, r := range rules {
		if skipInterface && interfacePermits([]*wf.Rule{r}) != 0 {
			continue
		}
		var conditions []string
		for _, c := range r.Conditions {
			conditions = append(conditions, fmt.Sprint(c.Field, c.Op, c.Value))
		}
		result = append(result, fmt.Sprint(r.Layer, r.Weight, r.Action, r.Persistent, conditions))
	}
	return result
}
func interfacePermits(rules []*wf.Rule) int {
	n := 0
	for _, r := range rules {
		for _, c := range r.Conditions {
			if c.Field == wf.FieldIPLocalInterface {
				n++
			}
		}
	}
	return n
}
func armFake(t *testing.T, f *fakeAPI, luid uint64) *Guard {
	t.Helper()
	plan, err := Plan(nil, false)
	if err != nil {
		t.Fatal(err)
	}
	var g *Guard
	if err = f.Transaction(func() error { var e error; g, e = arm(f, luid, "test-app", plan); return e }); err != nil {
		t.Fatal(err)
	}
	return g
}

// Without a tunnel adapter the rule set differs from the adapter rule set
// only by the missing interface permits.
func TestArmWithoutTunnelInterface(t *testing.T) {
	early, adapter := &fakeAPI{}, &fakeAPI{}
	armFake(t, early, 0)
	armFake(t, adapter, 42)
	if n := interfacePermits(early.rules); n != 0 {
		t.Fatal("interface permit without an adapter", n)
	}
	if n := interfacePermits(adapter.rules); n != 4 {
		t.Fatal("missing interface permits", n)
	}
	assertCoreExceptions(t, early.rules, true)
	if got, want := signatures(early.rules, false), signatures(adapter.rules, true); !reflect.DeepEqual(got, want) {
		t.Fatalf("early rule set differs beyond the interface permit:\n%v\n%v", got, want)
	}
}

// Re-arming with the adapter replaces the early rule set in one transaction.
func TestArmWithAdapterReplacesEarlyProtection(t *testing.T) {
	f := &fakeAPI{}
	early := armFake(t, f, 0)
	g := armFake(t, f, 42)
	if len(f.rules) != len(g.ids) {
		t.Fatal("early rules left behind", len(f.rules), len(g.ids))
	}
	current := map[wf.RuleID]bool{}
	for _, id := range g.ids {
		current[id] = true
	}
	for _, id := range early.ids {
		if current[id] {
			t.Fatal("early rule reused")
		}
	}
	for _, r := range f.rules {
		if !current[r.ID] {
			t.Fatal("rule not owned by the replacement guard")
		}
	}
	if n := interfacePermits(f.rules); n != 4 {
		t.Fatal("missing interface permits", n)
	}
	assertCoreExceptions(t, f.rules, true)
}

// Detach hands protection over without a gap: the filters stay until a later
// Arm, possibly from a new process, replaces them, and its Close removes all.
func TestDetachKeepsProtectionUntilReplaced(t *testing.T) {
	f := &fakeAPI{}
	early := armFake(t, f, 0)
	installed := len(f.rules)
	if err := early.Detach(); err != nil || !f.closed || len(f.rules) != installed {
		t.Fatal("detach changed protection", err, f.closed, len(f.rules))
	}
	if err := early.Detach(); err != nil {
		t.Fatal("second detach failed", err)
	}
	if err := early.Close(); !errors.Is(err, errDetached) || len(f.rules) != installed {
		t.Fatal("closing a detached guard removed protection", err, len(f.rules))
	}
	g := armFake(t, f.reopen(), 42)
	if len(f.rules) != len(g.ids) || interfacePermits(f.rules) != 4 {
		t.Fatal("new session did not replace detached protection", len(f.rules), len(g.ids))
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	if len(f.rules) != 0 || f.hasProvider || f.hasLayer || !f.closed {
		t.Fatal("close left Bimeron objects", len(f.rules), f.hasProvider, f.hasLayer, f.closed)
	}
}

// TestLiveCoreExceptionCondition installs the rule set in a WFP transaction
// that is always aborted, then verifies the conditions WFP accepted. It needs
// an elevated process and does not change committed WFP state.
func TestLiveCoreExceptionCondition(t *testing.T) {
	if os.Getenv("BIMERON_KILLSWITCH_LIVE") != "1" {
		t.Skip("set BIMERON_KILLSWITCH_LIVE=1 in an elevated session")
	}
	s, err := open()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if prior, err := owned(s); err != nil || len(prior) != 0 {
		t.Skip("existing Bimeron protection is present", err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	app, err := wf.AppID(exe)
	if err != nil {
		t.Fatal(err)
	}
	plan, _ := Plan(nil, false)
	abort := errors.New("abort")
	err = s.Transaction(func() error {
		if _, e := arm(s, 1, app, plan); e != nil {
			return e
		}
		rules, e := owned(s)
		if e != nil {
			return e
		}
		assertCoreExceptions(t, rules, false)
		return abort
	})
	if !errors.Is(err, abort) {
		t.Fatal(err)
	}
	if rules, err := owned(s); err != nil || len(rules) != 0 {
		t.Fatal("aborted transaction left filters", len(rules), err)
	}
}

// DNS ports are blocked outside the tunnel with priority over direct CIDR
// permits, and below the core, loopback and tunnel permits.
func TestDNSPortsBlockedAboveDirectRules(t *testing.T) {
	f := &fakeAPI{}
	armFake(t, f, 42)
	type portBlock struct {
		layer wf.LayerID
		field wf.FieldID
		proto uint8
		port  uint16
	}
	got := map[portBlock]int{}
	for _, r := range f.rules {
		if r.Action != wf.ActionBlock {
			continue
		}
		b := portBlock{layer: r.Layer}
		for _, c := range r.Conditions {
			switch c.Field {
			case wf.FieldIPProtocol:
				b.proto = c.Value.(uint8)
			case wf.FieldIPRemotePort, wf.FieldIPLocalPort:
				b.field, b.port = c.Field, c.Value.(uint16)
			}
		}
		if b.port == 0 {
			continue
		}
		got[b]++
		if r.Weight != ^uint64(0)-5 {
			t.Fatal("name port block has wrong weight", r.Weight, b)
		}
	}
	// DNS, DNS over TLS/QUIC, LLMNR and NetBIOS names are refused on connect;
	// LLMNR and NetBIOS names inbound too. mDNS (5353) is never blocked here.
	want := map[portBlock]int{}
	for _, layer := range []wf.LayerID{wf.LayerALEAuthConnectV4, wf.LayerALEAuthConnectV6} {
		for _, p := range []DNSPort{{6, 53}, {17, 53}, {6, 853}, {17, 853}, {17, 5355}, {6, 5355}, {17, 137}} {
			want[portBlock{layer, wf.FieldIPRemotePort, p.Protocol, p.Port}] = 1
		}
	}
	for _, layer := range []wf.LayerID{wf.LayerALEAuthRecvAcceptV4, wf.LayerALEAuthRecvAcceptV6} {
		for _, p := range []DNSPort{{17, 5355}, {6, 5355}, {17, 137}} {
			want[portBlock{layer, wf.FieldIPLocalPort, p.Protocol, p.Port}] = 1
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("name port blocks:\n got %v\nwant %v", got, want)
	}
	// DNS through the core, the tunnel and loopback must keep outweighing it;
	// these permits are the only ones matching the app, interface or loopback.
	for _, r := range f.rules {
		if r.Action != wf.ActionPermit || r.Weight > ^uint64(0)-5 {
			continue
		}
		for _, c := range r.Conditions {
			if c.Field == wf.FieldALEAppID || c.Field == wf.FieldIPLocalInterface {
				t.Fatal("core or tunnel permit does not outweigh the DNS block", r.Weight)
			}
			if prefix, ok := c.Value.(netip.Prefix); ok && prefix.Addr().IsLoopback() {
				t.Fatal("loopback permit does not outweigh the DNS block", r.Weight)
			}
		}
	}
	for _, r := range f.rules {
		if r.Action == wf.ActionPermit && r.Weight < ^uint64(0)-5 {
			for _, c := range r.Conditions {
				if c.Field == wf.FieldIPRemotePort {
					t.Fatal("port permit below the DNS block", r.Weight)
				}
			}
		}
	}
}

func TestImagePermittedMatchesProtectingExecutable(t *testing.T) {
	conditions, err := coreConditions("installed")
	if err != nil {
		t.Fatal(err)
	}
	rules := []*wf.Rule{{Action: wf.ActionPermit, Layer: wf.LayerALEAuthConnectV4, Conditions: conditions}}
	if !imagePermitted(rules, "installed") || imagePermitted(rules, "portable") {
		t.Fatal("core permit must match the installed app ID")
	}
}
