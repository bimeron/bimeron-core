package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"time"

	"bimeron/internal/dnsconfig"
	"bimeron/internal/hysteria2"
	"bimeron/internal/proxy"
	"bimeron/internal/sshtunnel"
	"bimeron/internal/trojan"
	"bimeron/internal/vless"
	"bimeron/internal/vpn"
	"golang.getoutline.org/sdk/transport"
)

func check(args []string) error {
	flags := flag.NewFlagSet("check", flag.ContinueOnError)
	dns := flags.String("dns", "1.1.1.1", "Comma-separated IPv4 DNS resolvers to test through the upstream proxy")
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
	var tcp transport.StreamDialer
	var udp transport.PacketListener
	if p.Type == "socks5" {
		s := &proxy.SOCKS5{Endpoint: p.TCP, Username: p.Username, Dialer: net.Dialer{Timeout: 15 * time.Second}}
		tcp, udp = s, s
	} else if p.Type == "vless" {
		client, err := vless.New(p, net.Dialer{Timeout: 15 * time.Second})
		if err != nil {
			return err
		}
		defer client.Close()
		tcp, udp = client, client
	} else if p.Type == "trojan" {
		client, err := trojan.New(p, net.Dialer{Timeout: 15 * time.Second})
		if err != nil {
			return err
		}
		defer client.Close()
		tcp, udp = client, client
	} else if p.Type == "hysteria2" {
		client, err := hysteria2.New(ctx, p, net.Dialer{Timeout: 15 * time.Second})
		if err != nil {
			return err
		}
		defer client.Close()
		tcp, udp = client, client
	} else if p.Type == "ssh" {
		client, err := sshtunnel.New(ctx, p, net.Dialer{Timeout: 15 * time.Second}, terminalSSHPrompt, true)
		if err != nil {
			return err
		}
		defer client.Close()
		tcp = client
	} else {
		tcp, err = proxy.Outline(p.TCP)
		if err != nil {
			return err
		}
		udp, err = proxy.OutlineUDP(p.UDP, net.Dialer{})
		if err != nil {
			return err
		}
	}
	if p.Type == "ssh" || (cfg != nil && cfg.Tunnel.Mode == "proxy" && p.Type == "socks5") {
		address, err := vpn.CheckTCP(ctx, tcp)
		if err != nil {
			return err
		}
		fmt.Printf("TCP/TLS check passed. Proxy IP: %s\n", address)
		return nil
	}
	address, err := vpn.Check(ctx, tcp, udp, resolvers)
	if err != nil {
		return err
	}
	fmt.Printf("TCP/TLS and UDP/DNS checks passed. Proxy IP: %s\n", address)
	return nil
}
