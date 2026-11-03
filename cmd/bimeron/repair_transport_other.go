//go:build !windows && !linux

package main

import (
	"errors"
	"net"
)

func listenRepairSession(string, uint32) (net.Listener, repairPeerCheck, func(), error) {
	return nil, nil, nil, errors.New("repair unsupported")
}

func newRepairBackend(string) (repairBackend, error) {
	return nil, errors.New("repair unsupported")
}
