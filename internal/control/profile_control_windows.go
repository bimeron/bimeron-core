//go:build windows

package control

import (
	"bimeron/internal/systemvpn"
	"context"
)

// RunProfileControl is a separate one-operation owner. It never starts a VPN.
func RunProfileControl(ctx context.Context, opts ForegroundOptions, cfg systemvpn.Config, remove bool) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	s, l, release, err := newForegroundOwner(opts)
	if err != nil {
		return err
	}
	defer release()
	s.endpoint = "ikev2_profile"
	wait := s.bindProfileControl(cfg, remove, func(c systemvpn.Config) (systemvpn.ProfilePlan, error) {
		return systemvpn.PrepareProfile(c, false, false)
	}, systemvpn.PrepareProfileReviewed)
	defer wait()
	return s.Serve(ctx, l)
}
