//go:build windows

package killswitch

import (
	"errors"
	"os"
	"reflect"
	"testing"

	"github.com/tailscale/wf"
	"golang.org/x/sys/windows"
)

// This fake never calls Windows; real WFP installation is a manual test.
type fakeAPI struct {
	rules        []*wf.Rule
	adds, failAt int
	deleteErr    bool
}

func (f *fakeAPI) Transaction(fn func() error) error {
	old := append([]*wf.Rule(nil), f.rules...)
	if err := fn(); err != nil {
		f.rules = old
		return err
	}
	return nil
}
func (f *fakeAPI) AddProvider(*wf.Provider) error { return nil }
func (f *fakeAPI) AddSublayer(*wf.Sublayer) error { return nil }
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
func (f *fakeAPI) DeleteSublayer(wf.SublayerID) error { return nil }
func (f *fakeAPI) DeleteProvider(wf.ProviderID) error { return nil }
func (f *fakeAPI) Close() error                       { return nil }
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
