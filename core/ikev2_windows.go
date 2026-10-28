//go:build windows

package core

import (
	"context"
	"time"

	"bimeron/internal/killswitch"
	"bimeron/internal/systemvpn"
	"bimeron/internal/windowsnet"
)

type ikev2Backend struct{}

func newIKEv2Backend() backend { return ikev2Backend{} }
func (ikev2Backend) Acquire(ctx context.Context) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !windowsnet.Elevated() {
		return nil, fault("administrator_required", false)
	}
	release, err := windowsnet.Acquire()
	if err != nil {
		return nil, fault("session_lock_failed", false)
	}
	pending, err := killswitch.Pending()
	if err != nil || pending {
		release()
		return nil, fault("ikev2_existing_kill_switch_requires_recovery", false)
	}
	return release, nil
}
func (ikev2Backend) Open(ctx context.Context, c SessionConfig, report func(string, string)) (session, error) {
	setup, cancel := context.WithTimeout(ctx, 75*time.Second)
	defer cancel()
	report("ikev2_connect", "Connecting through the Windows IKEv2 client")
	s, err := systemvpn.Open(setup, *c.IKEv2)
	if err != nil {
		if err == context.Canceled {
			return nil, err
		}
		if err == context.DeadlineExceeded {
			return nil, fault("ikev2_connect_timeout", false)
		}
		return nil, fault(err.Error(), false)
	}
	return s, nil
}
