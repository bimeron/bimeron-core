package main

import (
	"os"
	"slices"
	"syscall"
	"testing"
)

func TestShutdownSignalsCoverConsoleCloseAndHangup(t *testing.T) {
	for _, want := range []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP} {
		if !slices.Contains(shutdownSignals, want) {
			t.Fatalf("shutdown signals miss %v", want)
		}
	}
}
