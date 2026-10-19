//go:build darwin

package main

import (
	"context"
	"flag"
	"fmt"
	"bimeron/internal/macnet"
	"bimeron/internal/unixutil"
	"time"
)

func recoverVPN(args []string) error {
	flags := flag.NewFlagSet("recover", flag.ContinueOnError)
	keepDNS := flags.Bool("keep-current-dns", false, "Keep externally updated DNS during recovery")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("usage: bimeron recover [--keep-current-dns]")
	}
	if err := macnet.Requirements(); err != nil {
		return err
	}
	release, err := unixutil.Lock("vpn.lock")
	if err != nil {
		return err
	}
	defer release()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if err := macnet.NewManager().Recover(ctx, *keepDNS); err != nil {
		return err
	}
	fmt.Println("Removed stale Bimeron routes and restored owned DNS settings.")
	return nil
}
