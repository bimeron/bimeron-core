package main

import (
	"bimeron/internal/systemvpn"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
)

func ikev2Command(args []string) error {
	if len(args) > 0 && args[0] == "profile-control" {
		return profileControlCommand(args[1:])
	}
	if len(args) > 0 && args[0] == "foreground" {
		return foregroundCommand(args[1:])
	}
	if len(args) == 0 || args[0] != "profile" {
		return fmt.Errorf("usage: bimeron ikev2 profile -name <name> -server <DNS-name> [-apply | -remove]")
	}
	flags := flag.NewFlagSet("ikev2 profile", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	name := flags.String("name", "", "Current-user Windows profile name")
	server := flags.String("server", "", "Expected server DNS identity")
	apply := flags.Bool("apply", false, "Apply the previewed preparation")
	remove := flags.Bool("remove", false, "Explicitly remove an unchanged, inactive owned profile")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 || (*apply && *remove) {
		return fmt.Errorf("invalid IKEv2 profile arguments")
	}
	cfg := systemvpn.Config{WindowsProfile: *name, ServerName: *server}
	if err := cfg.Validate(); err != nil {
		return err
	}
	plan, err := systemvpn.PrepareProfile(cfg, *apply, *remove)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(plan)
}
