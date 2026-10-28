//go:build windows

package main

import (
	"bimeron/internal/killswitch"
	"bimeron/internal/windowsnet"
	"context"
	"fmt"
	"time"
)

func recoverVPN(args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("usage: bimeron recover")
	}
	if !windowsnet.Elevated() {
		return fmt.Errorf("recover requires an Administrator command prompt")
	}
	release, err := windowsnet.Acquire()
	if err != nil {
		return err
	}
	defer release()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if err := windowsnet.Recover(ctx); err != nil {
		return err
	}
	if err := windowsnet.RecoverIKEv2DNS(ctx); err != nil {
		return fmt.Errorf("could not restore native VPN DNS; protection retained")
	}
	if err := killswitch.Recover(); err != nil {
		return fmt.Errorf("could not remove owned kill switch protection")
	}
	fmt.Println("Removed stale Bimeron DNS and kill switch rules.")
	return nil
}
