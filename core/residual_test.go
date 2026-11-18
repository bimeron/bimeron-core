package core

import (
	"context"
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
	if s.State != Failed || s.LastError != "kill_switch_pending_run_recover" || !s.LastErrorPermanent || s.KillSwitch != KillSwitchResidual || s.Session != nil {
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
