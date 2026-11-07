//go:build linux || darwin

package main

import (
	core "bimeron/core"
	"bimeron/internal/control"
	"context"
	"fmt"
	"os"
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
	finishRecord, err := beginDeveloperRecord()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Developer recovery record unavailable: %v\n", err)
		finishRecord = func(bool) error { return nil }
	}
	ctx, stop := notifyShutdown(context.Background())
	defer stop()
	fmt.Println("Bimeron daemon ready. Use start, status, stop, shutdown or watch in another terminal.")
	err = control.NewServer(core.New(core.Options{})).Serve(ctx, l)
	if recordErr := finishRecord(err == nil); recordErr != nil {
		fmt.Fprintf(os.Stderr, "Developer cleanup record unavailable: %v\n", recordErr)
	}
	return err
}
