package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"bimeron/internal/accesskey"
	"bimeron/internal/config"
)

func loadConfig(flags *flag.FlagSet, path, command string) (*config.File, error) {
	if path == "" {
		return nil, nil
	}
	if flags.NArg() != 0 {
		return nil, fmt.Errorf("-config replaces the positional key file")
	}
	conflict := false
	flags.Visit(func(f *flag.Flag) {
		if f.Name != "config" {
			conflict = true
		}
	})
	if conflict {
		return nil, fmt.Errorf("-config cannot be combined with tunnel or policy flags; edit the config instead")
	}
	c, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	if command == "connect" && c.Tunnel.Mode != "vpn" {
		return nil, fmt.Errorf("connect requires [Interface] Mode = vpn")
	}
	if command == "proxy" && c.Tunnel.Mode != "proxy" {
		return nil, fmt.Errorf("proxy requires [Interface] Mode = proxy")
	}
	return c, nil
}
func resolveInput(ctx context.Context, path string, c *config.File) (accesskey.Profile, error) {
	if c != nil {
		return c.Resolve(ctx)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return accesskey.Profile{}, fmt.Errorf("could not read key file")
	}
	return accesskey.NewResolver().Resolve(ctx, string(b))
}
func validateConfig(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: bimeron validate <config-file>")
	}
	if _, err := config.Load(args[0]); err != nil {
		return err
	}
	fmt.Println("Configuration valid. No network requests or system changes performed.")
	return nil
}
func runConfig(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: bimeron run <config-file>")
	}
	c, err := config.Load(args[0])
	if err != nil {
		return err
	}
	if c.Tunnel.Mode == "proxy" {
		return serve([]string{"-config", args[0]})
	}
	return connect([]string{"-config", args[0]})
}
