//go:build linux || darwin

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	core "bimeron/core"
	"bimeron/internal/control"
	"syscall"
)

func daemon(args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("usage: bimeron daemon")
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("daemon requires root; use sudo")
	}
	l, err := control.Listen()
	if err != nil {
		return fmt.Errorf("cannot open control socket; another daemon may be running: %w", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	fmt.Println("Bimeron daemon ready. Use start, status, stop, shutdown or watch in another terminal.")
	return control.NewServer(core.New(core.Options{})).Serve(ctx, l)
}
