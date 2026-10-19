//go:build linux

package main

import (
	"context"
	"flag"
	"fmt"
	"bimeron/internal/linuxnet"
	"time"
)

func recoverVPN(args []string) error {
	flags := flag.NewFlagSet("recover", flag.ContinueOnError)
	keepDNS := flags.Bool("keep-current-dns", false, "Keep externally updated resolv.conf during recovery")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("usage: bimeron recover [--keep-current-dns]")
	}
	release, err := linuxnet.Lock("vpn.lock")
	if err != nil {
		return err
	}
	defer release()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	m := linuxnet.NewManager()
	if *keepDNS {
		if err := m.KeepCurrentDNS(); err != nil {
			return err
		}
	}
	if err := m.Recover(ctx, false); err != nil {
		return err
	}
	fmt.Println("Removed stale Bimeron routes, DNS and kill switch rules.")
	return nil
}
