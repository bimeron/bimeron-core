//go:build windows

package core

import (
	"context"
	"errors"
	"time"

	"bimeron/internal/killswitch"
	"bimeron/internal/windowsnet"
)

// FinalizeUpdateHold runs only for a repair operation authenticated by the service.
// authorize rechecks the protected intent and target while admission is closed.
// committed is invoked after WFP commit; its failure requires reconciliation.
func (e *Engine) FinalizeUpdateHold(ctx context.Context, profile, generation string, authorize, committed func() error) error {
	if !e.SupportsUpdateResume() || !validProfileID(profile) || !validProfileID(generation) || authorize == nil || committed == nil {
		return ErrUpdateResumeConflict
	}
	e.lifecycle.Lock()
	defer e.lifecycle.Unlock()
	e.mu.Lock()
	busy := e.active || e.exiting || e.maintenance != nil
	e.mu.Unlock()
	if busy {
		return ErrUpdateResumeConflict
	}
	release, err := windowsnet.BeginInstallationTransaction()
	if err != nil {
		return err
	}
	defer release()
	hold := e.opts.UpdateHold
	return finalizeHeldNetwork(ctx, func() error {
		if err := authorize(); err != nil {
			return err
		}
		record := hold.readRecord()
		if record.ProfileID != profile || record.Generation != generation {
			return ErrUpdateResumeConflict
		}
		return nil
	}, func(ctx context.Context) error {
		if err := windowsnet.Recover(ctx); err != nil {
			return err
		}
		if err := windowsnet.RecoverIKEv2DNS(ctx); err != nil {
			return err
		}
		pending, err := windowsnet.RestoreNetworkPending(ctx)
		if err != nil {
			return err
		}
		if pending {
			return errors.New("network recovery incomplete")
		}
		return nil
	}, func() error { return killswitch.RecoverGeneration(generation) }, func() error {
		e.mu.Lock()
		e.residual = false
		e.residualProfile = ""
		e.residualGeneration = ""
		e.residualChecked = time.Time{}
		e.mu.Unlock()
		return committed()
	})
}

func finalizeHeldNetwork(ctx context.Context, verify func() error, cleanup func(context.Context) error, remove, receipt func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := verify(); err != nil {
		return err
	}
	if err := cleanup(ctx); err != nil {
		return err
	}
	if err := verify(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := remove(); err != nil {
		return err
	}
	return receipt()
}

// InspectRestoreProtection reads the live machine under the same exclusion as finalize.
// It never refreshes the ordinary status cache or removes a stale marker.
func (e *Engine) InspectRestoreProtection(ctx context.Context, profile, generation string) string {
	e.lifecycle.Lock()
	defer e.lifecycle.Unlock()
	e.mu.Lock()
	busy := e.active || e.exiting || e.maintenance != nil || e.status.Session != nil
	e.mu.Unlock()
	if busy || e.opts.UpdateHold == nil {
		return "unavailable"
	}
	release, err := windowsnet.BeginInstallationTransaction()
	if err != nil {
		return "unavailable"
	}
	defer release()
	if r := e.opts.UpdateHold.readRecord(); r.ProfileID == profile && r.Generation == generation {
		return "held"
	}
	pending, err := killswitch.Pending()
	if err != nil || pending {
		return "unavailable"
	}
	pending, err = windowsnet.RestoreNetworkPending(ctx)
	if err != nil || pending {
		return "unavailable"
	}
	return "clear"
}
