//go:build linux

package core

import "bimeron/internal/linuxnet"

// residualProtection reports a guard that no running session owns. A held
// session lock means another process (for example a foreground connect) owns
// the session and its protection.
func residualProtection() (bool, error) {
	release, err := linuxnet.Lock("vpn.lock")
	if err != nil {
		return false, nil
	}
	defer release()
	s, err := linuxnet.NewManager().Load()
	return s != nil && s.Guard, err
}
