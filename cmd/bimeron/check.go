package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"bimeron/internal/dnsconfig"

	"bimeron/internal/proxy"
	"bimeron/internal/vpn"
)

func check(args []string) error {
	flags := flag.NewFlagSet("check", flag.ContinueOnError)
	dns := flags.String("dns", "1.1.1.1", "Comma-separated IPv4 DNS resolvers to test through Outline")
	configPath := flags.String("config", "", "Bimeron config file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	cfg, err := loadConfig(flags, *configPath, "check")
	if err != nil {
		return err
	}
	if cfg != nil {
		*dns = cfg.Tunnel.DNS
	}
	if cfg == nil && flags.NArg() != 1 {
		return fmt.Errorf("usage: bimeron check [-dns 1.1.1.1] <key-file>")
	}
	resolvers, err := dnsconfig.Parse(*dns)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	p, err := resolveInput(ctx, flags.Arg(0), cfg)
	if err != nil {
		return err
	}
	tcp, err := proxy.Outline(p.TCP)
	if err != nil {
		return err
	}
	udp, err := proxy.OutlineUDP(p.UDP, net.Dialer{})
	if err != nil {
		return err
	}
	address, err := vpn.Check(ctx, tcp, udp, resolvers)
	if err != nil {
		return err
	}
	fmt.Printf("TCP/TLS and UDP/DNS checks passed. Outline IP: %s\n", address)
	return nil
}
