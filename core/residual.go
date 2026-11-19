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
	// The probe may take the session lock for an instant; never race a Start.
	if !e.lifecycle.TryLock() {
		return
	}
	defer e.lifecycle.Unlock()
	e.mu.Lock()
	if e.active || time.Since(e.residualChecked) < residualInterval {
		e.mu.Unlock()
		return
	}
	e.residualChecked = time.Now()
	probe := e.residualProbe
	e.mu.Unlock()
	found, err := probe()
	// The update record outlives only the protection it describes. Residual
	// protection can also be reported as not found while another process
	// owns the session, so the record is removed only when no Bimeron
	// protection is installed at all.
	profile := ""
	if hold := e.opts.UpdateHold; hold != nil {
		if found {
			profile = hold.Read()
		} else if err == nil {
			if installed, inspectErr := e.installedProbe(); inspectErr == nil && !installed {
				_ = hold.Clear()
			}
		}
	}
	e.mu.Lock()
	e.residual = found || err != nil && e.residual
	if found || err == nil {
		e.residualProfile = profile
	}
	e.mu.Unlock()
}

// probeResidual reports protection that no owner holds. installed reports
// whether protection is installed; owner reports whether another owner holds
// the session, and may return a release for a lock it took to find out.
// Protection is checked again before that release: an owner that stopped in
// between removed its protection before it released the session, and must
// not be reported as residual. An unknown owner state is not residual.
func probeResidual(installed func() (bool, error), owner func() (release func(), held bool, err error)) (bool, error) {
	present, err := installed()
	if err != nil || !present {
		return false, err
	}
	release, held, err := owner()
	if release != nil {
		defer release()
	}
	if err != nil || held {
		return false, nil
	}
	return installed()
}

// residualStatusLocked reports idle residual protection as failed with
// cleanup_failed_run_recover, the code existing GUIs already route to network
// recovery, unless another terminal failure is already reported.
func (e *Engine) residualStatusLocked(status *Status) {
	if e.active || !e.residual {
		return
	}
	status.KillSwitch = KillSwitchResidual
	if e.residualProfile != "" {
		status.ResidualReason = ResidualUpdate
		status.ResidualProfile = e.residualProfile
	}
	if status.State == Failed && status.LastError != "" {
		return
	}
	status.State = Failed
	status.LastError = "cleanup_failed_run_recover"
	status.LastErrorPermanent = true
}
