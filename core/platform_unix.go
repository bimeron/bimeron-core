//go:build linux || darwin

package core

import (
	"errors"

	"bimeron/internal/unixutil"
)

// requirementsFault reports why this host cannot run VPN mode.
func requirementsFault(err error) error {
	if errors.Is(err, unixutil.ErrRootRequired) {
		return fault("administrator_required", false)
	}
	return fault("vpn_requirements_missing", false)
}
