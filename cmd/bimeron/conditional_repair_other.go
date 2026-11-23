//go:build !windows

package main

import (
	"errors"
	"net"
)

func conditionalRepairSession(net.Conn, string, []byte) error {
	return errors.New("unsupported repair protocol")
}
