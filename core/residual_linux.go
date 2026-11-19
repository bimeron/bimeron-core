//go:build linux

package core

import "bimeron/internal/linuxnet"

// residualProtection reports a guard that no running session owns. The
// session lock is taken only when a guard is journaled, and only for an
// instant while the journal is read again: a held lock means another process
// owns the session. Owners retry that lock briefly (linuxnet.LockSession), so
// the probe does not fail them.
func residualProtection() (bool, error) {
	return probeResidual(journaledGuard, func() (func(), bool, error) {
		release, err := linuxnet.Lock("vpn.lock")
		if err != nil {
			return nil, true, nil
		}
		return release, false, nil
	})
}

func journaledGuard() (bool, error) {
	s, err := linuxnet.NewManager().Load()
	if err != nil || s == nil {
		return false, err
	}
	return s.Guard, nil
}

// protectionInstalled reports a journaled guard, owned or not.
func protectionInstalled() (bool, error) { return journaledGuard() }
