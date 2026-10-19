package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	core "bimeron/core"
	"bimeron/internal/routing"
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
		session = core.KeyFile(flags.Arg(0))
		session.Mode = "proxy"
		session.Listen = *listen
		if *policyFile != "" {
			b, e := os.ReadFile(*policyFile)
			if e != nil {
				return fmt.Errorf("could not read policy")
			}
			var p routing.Config
			if json.Unmarshal(b, &p) != nil {
				return fmt.Errorf("invalid policy JSON")
			}
			session.Policy, err = routing.Compile(p)
		}
	}
	if err != nil {
		return err
	}
	return runSession(session)
}
