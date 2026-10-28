//go:build !windows

package systemvpn

import "errors"

func PrepareProfile(Config, bool, bool) (ProfilePlan, error) {
	return ProfilePlan{}, errors.New("ikev2_profile_preparation_requires_windows")
}
