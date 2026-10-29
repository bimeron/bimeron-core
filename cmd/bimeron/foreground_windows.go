//go:build windows

package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"os/signal"

	"bimeron/internal/control"
	"bimeron/internal/systemvpn"
)

func foregroundCommand(args []string) error {
	flags := flag.NewFlagSet("ikev2 foreground", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	config := flags.String("config", "", "Absolute native configuration path")
	digest := flags.String("sha256", "", "Reviewed configuration SHA256")
	requester := flags.Uint("requester-pid", 0, "Requesting GUI PID")
	created := flags.Uint64("requester-created", 0, "Requesting GUI creation FILETIME")
	if flags.Parse(args) != nil || flags.NArg() != 0 || uint64(*requester) > 0xffffffff {
		return errors.New("invalid_foreground_arguments")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	return control.RunForeground(ctx, control.ForegroundOptions{Config: *config, SHA256: *digest, RequesterPID: uint32(*requester), RequesterCreated: *created})
}

func profileControlCommand(args []string) error {
	f := flag.NewFlagSet("ikev2 profile-control", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	name := f.String("name", "", "Current-user profile")
	server := f.String("server", "", "Server DNS identity")
	action := f.String("action", "apply", "apply or remove")
	pid := f.Uint("requester-pid", 0, "GUI PID")
	created := f.Uint64("requester-created", 0, "GUI creation FILETIME")
	if f.Parse(args) != nil || f.NArg() != 0 || uint64(*pid) > 0xffffffff || (*action != "apply" && *action != "remove") {
		return errors.New("invalid_foreground_arguments")
	}
	return control.RunProfileControl(context.Background(), control.ForegroundOptions{RequesterPID: uint32(*pid), RequesterCreated: *created}, systemvpn.Config{WindowsProfile: *name, ServerName: *server}, *action == "remove")
}
