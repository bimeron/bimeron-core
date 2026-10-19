//go:build darwin

package core

import (
	"context"
	"testing"
)

func TestMacOSRejectsUnsupportedKillSwitchBeforeSetup(t *testing.T) {
	p := newPlatform(SessionConfig{KillSwitch: true})
	release, err := p.Acquire(context.Background())
	if release != nil || err == nil || err.Error() != "kill_switch_unsupported_on_macos" {
		t.Fatal("unsupported protection was not rejected", err)
	}
}
