//go:build !windows

package main

import (
	"errors"
	"net"
)

func guardedRepairSession(net.Conn, string, heldRestoreRequest) error {
	return errors.New("guarded restore requires Windows")
}
