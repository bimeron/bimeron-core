//go:build linux

package core

import "bimeron/internal/linuxnet"

func residualProtection() (bool, error) {
	s, err := linuxnet.NewManager().Load()
	return s != nil && s.Guard, err
}
