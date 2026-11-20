package main

import (
	core "bimeron/core"
	"bimeron/internal/config"
	"bimeron/internal/routing"
	"flag"
	"fmt"
)

func serve(args []string) error {
	flags := flag.NewFlagSet("proxy", flag.ContinueOnError)
	listen := flags.String("listen", "127.0.0.1:1080", "loopback SOCKS5 address")
	policyFile := flags.String("policy", "", "optional routing policy JSON")
	configPath := flags.String("config", "", "Bimeron config file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	cfg, err := loadConfig(flags, *configPath, "proxy")
	if err != nil {
		return err
	}
	var session core.SessionConfig
	if cfg != nil {
		session, err = core.FromConfig(cfg)
	} else {
		if flags.NArg() != 1 {
			return fmt.Errorf("usage: bimeron proxy [-listen 127.0.0.1:1080] [-policy file.json] <key-file>")
		}
		if config.IsWireGuardFile(flags.Arg(0)) {
			return serveWireGuard(flags.Arg(0), *listen, *policyFile)
		}
		session = core.KeyFile(flags.Arg(0))
		session.Mode = "proxy"
		session.Listen = *listen
		if *policyFile != "" {
			var p routing.Config
			if err := readPolicy(*policyFile, "policy", &p); err != nil {
				return err
			}
			session.Policy, err = routing.Compile(p)
		}
	}
	if err != nil {
		return err
	}
	return runSession(session)
}

// serveWireGuard runs a plain WireGuard or AmneziaWG file as a local SOCKS5
// proxy. AllowedIPs alone decide what uses the tunnel; with -policy the
// policy decides and destinations outside AllowedIPs go direct. DNS for
// names comes from the file's [Interface]. No adapter, route or system DNS
// is created.
func serveWireGuard(path, listen, policyFile string) error {
	c, err := config.LoadWireGuard(path)
	if err != nil {
		return err
	}
	c.Tunnel.Mode, c.Tunnel.Listen = "proxy", listen
	session, err := core.FromConfig(c)
	if err != nil {
		return err
	}
	if policyFile != "" {
		var p routing.Config
		if err := readPolicy(policyFile, "policy", &p); err != nil {
			return err
		}
		if session.Policy, err = routing.Compile(p); err != nil {
			return err
		}
		session.AllowedIPsMode = "direct"
	}
	return runSession(session)
}
