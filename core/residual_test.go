package core

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
)

// An idle daemon reports protection that no run owns, for example filters
// kept after a power loss, so GUIs can guide the user to recover.
func TestIdleEngineReportsResidualProtection(t *testing.T) {
	var found atomic.Bool
	var probes atomic.Int32
	e := testEngine(fakeBackend{open: func(context.Context) (session, error) {
		return nil, fault("cleanup_failed_run_recover", false)
	}})
	e.opts.ResidualProtection = true
	e.residualProbe = func() (bool, error) { probes.Add(1); return found.Load(), nil }
	if s := e.Status(); s.State != Disconnected || s.KillSwitch != "" {
		t.Fatal(s)
	}
	found.Store(true)
	e.residualChecked = e.residualChecked.AddDate(-1, 0, 0)
	s := e.Status()
	if s.State != Failed || s.LastError != "cleanup_failed_run_recover" || !s.LastErrorPermanent || s.KillSwitch != KillSwitchResidual || s.Session != nil {
		t.Fatal(s)
	}
	before := probes.Load()
	e.Status()
	if probes.Load() != before {
		t.Fatal("residual probe not rate limited")
	}
	// A run that ends with its own recovery code keeps it.
	ctx := testDeadline(t)
	if err := e.Start(ctx, testConfig()); err != nil {
		t.Fatal(err)
	}
	_ = e.Wait(ctx)
	if s := e.Status(); s.State != Failed || s.LastError != "cleanup_failed_run_recover" || s.KillSwitch != KillSwitchResidual {
		t.Fatal(s)
	}
	found.Store(false)
	e.mu.Lock()
	e.residualChecked = e.residualChecked.AddDate(-1, 0, 0)
	e.mu.Unlock()
	if s := e.Status(); s.KillSwitch != "" || s.LastError != "cleanup_failed_run_recover" {
		t.Fatal("recovered protection still reported", s)
	}
}

func TestResidualProtectionIsOptIn(t *testing.T) {
	e := testEngine(fakeBackend{})
	e.residualProbe = func() (bool, error) { t.Fatal("probe without opt-in"); return true, nil }
	if s := e.Status(); s.State != Disconnected {
		t.Fatal(s)
	}
}

// The probe checks the owner only when protection is installed, and checks
// the protection again before releasing a lock it took: an owner that
// stopped in between removed its protection before releasing the session and
// is not residual. An unknown owner state is not residual either.
func TestProbeResidualOrder(t *testing.T) {
	errInspect := errors.New("inspect")
	for _, tc := range []struct {
		name      string
		installed []bool
		inspect   error
		held      bool
		heldErr   error
		want      bool
		wantErr   error
		calls     string
	}{
		{name: "none", installed: []bool{false}, calls: "i"},
		{name: "inspect error", installed: []bool{false}, inspect: errInspect, wantErr: errInspect, calls: "i"},
		{name: "owned", installed: []bool{true}, held: true, calls: "ilu"},
		{name: "lock unknown", installed: []bool{true}, heldErr: errors.New("lock"), calls: "ilu"},
		{name: "owner stopped meanwhile", installed: []bool{true, false}, calls: "iliu"},
		{name: "residual", installed: []bool{true, true}, want: true, calls: "iliu"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls string
			inspections := 0
			installed := func() (bool, error) {
				calls += "i"
				present := tc.installed[inspections]
				inspections++
				return present, tc.inspect
			}
			owner := func() (func(), bool, error) {
				calls += "l"
				return func() { calls += "u" }, tc.held, tc.heldErr
			}
			got, err := probeResidual(installed, owner)
			if got != tc.want || !errors.Is(err, tc.wantErr) || calls != tc.calls {
				t.Fatalf("probe = %v, %v after %q; want %v, %v after %q", got, err, calls, tc.want, tc.wantErr, tc.calls)
			}
		})
	}
}
