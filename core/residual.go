package core

import "time"

// KillSwitchResidual marks kill switch protection that no run owns, for
// example filters kept after a crash, power loss or failed cleanup.
const KillSwitchResidual = "residual"

// residualInterval bounds how often an idle engine inspects residual
// protection; Status is polled frequently by GUIs.
const residualInterval = 5 * time.Second

// refreshResidual updates the cached residual-protection result while no run
// is active. It never runs the platform probe under Engine.mu.
func (e *Engine) refreshResidual() {
	if !e.opts.ResidualProtection {
		return
	}
	e.mu.Lock()
	if e.active || time.Since(e.residualChecked) < residualInterval {
		e.mu.Unlock()
		return
	}
	e.residualChecked = time.Now()
	probe := e.residualProbe
	e.mu.Unlock()
	found, err := probe()
	e.mu.Lock()
	e.residual = found || err != nil && e.residual
	e.mu.Unlock()
}

// residualStatusLocked reports idle residual protection as failed with
// cleanup_failed_run_recover, the code existing GUIs already route to network
// recovery, unless another terminal failure is already reported.
func (e *Engine) residualStatusLocked(status *Status) {
	if e.active || !e.residual {
		return
	}
	status.KillSwitch = KillSwitchResidual
	if status.State == Failed && status.LastError != "" {
		return
	}
	status.State = Failed
	status.LastError = "cleanup_failed_run_recover"
	status.LastErrorPermanent = true
}
