//go:build windows

package core

import (
	"bimeron/internal/killswitch"
	"bimeron/internal/windowsnet"
)

// residualProtection reports filters that no running session owns. A held
// session lock means another process (for example a foreground connect) owns
// the session and its protection.
func residualProtection() (bool, error) {
	release, err := windowsnet.Acquire()
	if err != nil {
		return false, nil
	}
	defer release()
	return killswitch.Pending()
}
