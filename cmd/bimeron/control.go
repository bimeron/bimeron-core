package main

import (
	core "bimeron/core"
	"bimeron/internal/control"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

func controlCommand(command string, args []string) error {
	r := control.Request{Command: command}
	if command == "start" {
		if len(args) != 1 {
			return fmt.Errorf("usage: bimeron start <config-file>")
		}
		p, err := filepath.Abs(args[0])
		if err != nil {
			return err
		}
		r.Config = p
	} else if len(args) != 0 {
		return fmt.Errorf("usage: bimeron %s", command)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	a, err := control.Call(ctx, r)
	if err != nil {
		return err
	}
	fmt.Printf("%s (attempt %d)\n", a.Status.State, a.Status.Attempt)
	if command == "status" && a.Status.Session != nil {
		s := a.Status.Session
		fmt.Printf("Session: %s; active: %t; mode: %s; IPv6: %s; kill switch requested: %t\n", s.ID, s.Active, s.Mode, s.IPv6, s.KillSwitchRequested)
		if s.ProfileName != "" {
			fmt.Printf("Profile: %s\n", s.ProfileName)
		}
		if s.ProfileID != "" {
			fmt.Printf("Profile ID: %s\n", s.ProfileID)
		}
		if s.ServerTCP != "" {
			fmt.Printf("Server TCP: %s", s.ServerTCP)
			if s.ServerTCPName != "" {
				fmt.Printf(" (%s)", s.ServerTCPName)
			}
			fmt.Println()
		}
		if s.ServerUDP != "" {
			fmt.Printf("Server UDP: %s", s.ServerUDP)
			if s.ServerUDPName != "" {
				fmt.Printf(" (%s)", s.ServerUDPName)
			}
			fmt.Println()
		}
	}
	if a.Status.LastError != "" {
		fmt.Println("Last error:", a.Status.LastError)
	}
	if command == "start" {
		fmt.Println("Start accepted. Use bimeron status or watch to follow connection.")
	}
	if command == "stop" {
		fmt.Println("Session disconnected. Daemon remains running.")
	}
	if command == "shutdown" {
		fmt.Println("Daemon shutdown accepted; session cleanup completed.")
	}
	return nil
}
func statsControl(args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("usage: bimeron stats")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	a, err := control.Call(ctx, control.Request{Command: "stats"})
	if err != nil {
		return err
	}
	if a.Stats == nil {
		return fmt.Errorf("daemon did not report statistics")
	}
	return json.NewEncoder(os.Stdout).Encode(a.Stats)
}

func capabilitiesControl(args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("usage: bimeron capabilities")
	}
	c := core.PlatformCapabilities()
	return json.NewEncoder(os.Stdout).Encode(c)
}

func watchControl(args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("usage: bimeron watch")
	}
	ctx, stop := notifyShutdown(context.Background())
	defer stop()
	return watchEvents(ctx, control.Call, os.Stdout, defaultWatchTiming)
}

type watchTiming struct{ poll, retryMin, retryMax time.Duration }

var defaultWatchTiming = watchTiming{poll: time.Second, retryMin: 100 * time.Millisecond, retryMax: time.Second}

// watchEvents follows daemon events until ctx is canceled. When no daemon
// answers, for example while it restarts, it retries with bounded backoff;
// errors reported by a daemon still end the watch.
func watchEvents(ctx context.Context, call func(context.Context, control.Request) (control.Response, error), out io.Writer, timing watchTiming) error {
	var cursor uint64
	var instance string
	var retry time.Duration
	for {
		callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		a, err := call(callCtx, control.Request{Command: "events", After: cursor})
		cancel()
		if ctx.Err() != nil {
			return nil
		}
		delay := timing.poll
		if err != nil && a.Version == 0 {
			if retry == 0 {
				fmt.Fprintln(out, "Daemon unavailable; retrying:", err)
				retry = timing.retryMin
			} else {
				retry = min(2*retry, timing.retryMax)
			}
			delay = retry
		} else {
			retry = 0
			if a.Instance != "" && instance != "" && instance != a.Instance {
				fmt.Fprintln(out, "Daemon restarted; resetting event cursor.")
				cursor = 0
				instance = a.Instance
				continue
			}
			if err != nil {
				return err
			}
			instance = a.Instance
			if a.Dropped {
				fmt.Fprintln(out, "Some events were skipped; current state:", a.Status.State)
			}
			for _, e := range a.Events {
				fmt.Fprintf(out, "%s [%s] %s\n", e.Event.Time.Format("15:04:05"), e.Event.State, e.Event.Message)
				if e.Event.LastError != "" {
					fmt.Fprintln(out, "Reason:", e.Event.LastError)
				}
			}
			cursor = a.Cursor
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}
