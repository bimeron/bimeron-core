package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

// shutdownSignals request an orderly stop with session and network cleanup.
// On Windows the Go runtime reports console close, logoff, and shutdown events
// as SIGTERM and blocks the console handler while cleanup runs; Windows still
// terminates the process when its own grace period expires. SIGHUP covers a
// terminal hangup or a dropped SSH connection on Unix and is never delivered
// on Windows.
var shutdownSignals = []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP}

func notifyShutdown(parent context.Context) (context.Context, context.CancelFunc) {
	return signal.NotifyContext(parent, shutdownSignals...)
}
