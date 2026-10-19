//go:build windows

package killswitch

import (
	"errors"
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
