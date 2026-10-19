//go:build windows || linux || darwin

package main

import (
	"flag"
	"fmt"
	core "bimeron/core"
	"bimeron/internal/dnsconfig"
)

func connect(args []string) error {
	flags := flag.NewFlagSet("connect", flag.ContinueOnError)
	policyPath := flags.String("policy", "", "IP/CIDR routing policy JSON")
	dns := flags.String("dns", "1.1.1.1", "Comma-separated IPv4 DNS resolvers")
	configPath := flags.String("config", "", "Bimeron config file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	cfg, err := loadConfig(flags, *configPath, "connect")
	if err != nil {
		return err
	}
	var session core.SessionConfig
	if cfg != nil {
		session, err = core.FromConfig(cfg)
	} else {
		if flags.NArg() != 1 {
			return fmt.Errorf("usage: bimeron connect [-policy file.json] [-dns 1.1.1.1] <key-file>")
		}
		session = core.KeyFile(flags.Arg(0))
		session.Policy, err = vpnPolicy(*policyPath)
		if err == nil {
			session.DNS, err = dnsconfig.Parse(*dns)
		}
	}
	if err != nil {
		return err
	}
	return runSession(session)
}
