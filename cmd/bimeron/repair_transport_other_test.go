//go:build !windows && !linux

package main

import "testing"

func TestUnsupportedRepairDoesNotCreateResources(t *testing.T) {
	backend, err := newRepairBackend("caller")
	if backend != nil || err == nil || err.Error() != "repair unsupported" {
		t.Fatalf("unsupported backend accepted: %v, %v", backend, err)
	}
	listener, authenticate, release, err := listenRepairSession("nonce", 1)
	if listener != nil || authenticate != nil || release != nil || err == nil || err.Error() != "repair unsupported" {
		t.Fatal("unsupported platform created repair transport resources")
	}
}
