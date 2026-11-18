//go:build linux

package core

import "bimeron/internal/linuxnet"

// residualProtection reports a guard that no running session owns. The
// session lock is taken only when a guard is journaled, and only for an
// instant: a held lock means another process owns the session.
func residualProtection() (bool, error) {
	s, err := linuxnet.NewManager().Load()
	if err != nil || s == nil || !s.Guard {
		return false, err
	}
	release, err := linuxnet.Lock("vpn.lock")
	if err != nil {
		return false, nil
	}
	release()
	return true, nil
}
