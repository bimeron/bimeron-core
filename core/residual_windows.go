//go:build windows

package core

import (
	"bimeron/internal/killswitch"
	"bimeron/internal/windowsnet"
)

// residualProtection reports filters that no running session owns. The
// session lock is inspected without being taken: a held lock or a live
// foreground owner means another process owns the session and its
// protection, and an abandoned lock keeps its state for installers.
func residualProtection() (bool, error) {
	return probeResidual(killswitch.Pending, func() (func(), bool, error) {
		held, err := windowsnet.SessionLockHeld()
		return func() {}, held, err
	})
}

// protectionInstalled reports Bimeron packet kill switch filters, owned or not.
func protectionInstalled() (bool, error) { return killswitch.Pending() }
