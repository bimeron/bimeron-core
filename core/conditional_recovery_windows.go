package core

import (
	"context"
	"errors"
	"os"
	"time"

	"bimeron/internal/killswitch"
	"bimeron/internal/windowsnet"
)

// ConditionalRecovery inspects with an empty expected generation. Only this
// live process can attest to installing the exact set of persistent rules.
func (e *Engine) ConditionalRecovery(ctx context.Context, expected string) (string, string) {
	owned := killswitch.ProcessGeneration()
	if owned == "" || (expected != "" && owned != expected) {
		return "", "conflict"
	}
	if !e.lifecycle.TryLock() {
		return "", "conflict"
	}
	defer e.lifecycle.Unlock()
	e.mu.Lock()
	busy := e.active || e.exiting || e.maintenance != nil || !e.residual
	e.mu.Unlock()
	if busy || e.opts.UpdateHold == nil {
		return "", "conflict"
	}
	releaseUpdate, err := windowsnet.BeginServiceUpdate(false)
	if err != nil {
		return "", "conflict"
	}
	defer releaseUpdate()
	unlock, err := windowsnet.BeginInstallationTransaction()
	if err != nil {
		return "", "unknown"
	}
	defer unlock()
	generation, result := recoverOwnedRules(ctx, expected, owned, e.opts.UpdateHold.Path, killswitch.FilterGeneration, windowsnet.RestoreNetworkPending, killswitch.RecoverGeneration)
	if result != "recovered" {
		return generation, result
	}
	e.mu.Lock()
	e.residual = false
	e.residualChecked = time.Time{}
	e.mu.Unlock()
	return owned, "recovered"
}

// The caller holds lifecycle, update and network exclusion. A process only
// records regular packet guard IDs, so a native or mixed set cannot match.
func recoverOwnedRules(ctx context.Context, expected, owned, marker string,
	installed func() (string, error), networkPending func(context.Context) (bool, error),
	remove func(string) error) (string, string) {
	if owned == "" || (expected != "" && expected != owned) {
		return "", "conflict"
	}
	if _, err := os.Lstat(marker); err == nil {
		return "", "conflict"
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", "unknown"
	}
	current, err := installed()
	if err != nil {
		return "", "unknown"
	}
	if current != owned {
		return "", "conflict"
	}
	if pending, err := networkPending(ctx); err != nil || pending {
		return "", "unknown"
	}
	if expected == "" {
		return owned, "eligible"
	}
	if ctx.Err() != nil || remove(expected) != nil {
		return "", "unknown"
	}
	return owned, "recovered"
}
