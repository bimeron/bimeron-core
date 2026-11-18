//go:build windows

package core

import (
	"bimeron/internal/killswitch"
	"bimeron/internal/windowsnet"
)

// residualProtection reports filters that no running session owns. The
// session lock is taken only when filters exist, and only for an instant: a
// held lock means another process (for example a foreground connect) owns the
// session and its protection.
func residualProtection() (bool, error) {
	pending, err := killswitch.Pending()
	if err != nil || !pending {
		return false, err
	}
	release, err := windowsnet.Acquire()
	if err != nil {
		return false, nil
	}
	release()
	return true, nil
}
