//go:build windows

package main

import (
	core "bimeron/core"
	"bimeron/internal/control"
	"bimeron/internal/windowsnet"
	"context"
	"fmt"
	"os"
	"os/signal"
)

func daemon(args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("usage: bimeron daemon")
	}
	if !windowsnet.Elevated() {
		return fmt.Errorf("daemon requires an Administrator command prompt")
	}
	l, err := control.Listen()
	if err != nil {
		return fmt.Errorf("cannot open control pipe; another daemon may already be running")
	}
	finishRecord, err := beginDeveloperRecord()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Developer recovery record unavailable: %v\n", err)
		finishRecord = func(bool) error { return nil }
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	fmt.Println("Bimeron daemon ready. Use start, status, stop, shutdown or watch in another CMD.")
	fmt.Println("Ctrl+C stops the daemon and its VPN session.")
	err = control.NewServer(core.New(core.Options{})).Serve(ctx, l)
	if recordErr := finishRecord(err == nil); recordErr != nil {
		fmt.Fprintf(os.Stderr, "Developer cleanup record unavailable: %v\n", recordErr)
	}
	return err
}
