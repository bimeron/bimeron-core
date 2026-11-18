//go:build windows

package core

import "bimeron/internal/killswitch"

func residualProtection() (bool, error) { return killswitch.Pending() }
