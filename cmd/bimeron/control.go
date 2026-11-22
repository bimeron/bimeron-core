package main

import (
	core "bimeron/core"
	"bimeron/internal/control"
	"bimeron/internal/displaytext"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// shown prepares daemon-supplied text for one terminal line. A genuine daemon
// sends no control characters, but the CLI does not rely on that.
func shown[T ~string](s T) string { return displaytext.Line(string(s)) }

// writeDaemonJSON writes v, which holds daemon-supplied text, as one JSON line
// with control and bidirectional formatting characters escaped.
func writeDaemonJSON(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = w.Write(append(displaytext.EscapeJSON(b), '\n'))
	return err
}

func controlCommand(command string, args []string) error {
	r := control.Request{Command: command}
	if command == "reconnect" {
		r.Command = "reconnect_now"
	}
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
	printControlResult(os.Stdout, command, a)
	return nil
}

// printControlResult prints the daemon's answer to a control command.
func printControlResult(out io.Writer, command string, a control.Response) {
	fmt.Fprintf(out, "%s (attempt %d)\n", shown(a.Status.State), a.Status.Attempt)
	if command == "status" && a.Status.Session != nil {
		s := a.Status.Session
		fmt.Fprintf(out, "Session: %s; active: %t; mode: %s; IPv6: %s; kill switch requested: %t\n", shown(s.ID), s.Active, shown(s.Mode), shown(s.IPv6), s.KillSwitchRequested)
		if s.ProfileName != "" {
			fmt.Fprintf(out, "Profile: %s\n", shown(s.ProfileName))
		}
		if s.ProfileID != "" {
			fmt.Fprintf(out, "Profile ID: %s\n", shown(s.ProfileID))
		}
		if s.ServerTCP != "" {
			fmt.Fprintf(out, "Server TCP: %s", shown(s.ServerTCP))
			if s.ServerTCPName != "" {
				fmt.Fprintf(out, " (%s)", shown(s.ServerTCPName))
			}
			fmt.Fprintln(out)
		}
		if s.ServerUDP != "" {
			fmt.Fprintf(out, "Server UDP: %s", shown(s.ServerUDP))
			if s.ServerUDPName != "" {
				fmt.Fprintf(out, " (%s)", shown(s.ServerUDPName))
			}
			fmt.Fprintln(out)
		}
	}
	if a.Status.LastError != "" {
		fmt.Fprintln(out, "Last error:", shown(a.Status.LastError))
	}
	if a.Status.KillSwitch == core.KillSwitchHolding {
		fmt.Fprintln(out, "Kill switch holding: traffic outside the tunnel stays blocked until connection or stop.")
	}
	if a.Status.KillSwitch == core.KillSwitchResidual {
		if a.Status.ResidualReason == core.ResidualUpdate {
			fmt.Printf("Kill switch protection was kept across a service update for profile ID %s; start that profile again to reconnect.\n", a.Status.ResidualProfile)
		} else {
			fmt.Println("Kill switch protection remains installed without a session; start a kill switch profile or run bimeron recover.")
		}
	}
	if a.Status.State == core.Reconnecting && !a.Status.NextAttemptAt.IsZero() {
		fmt.Fprintln(out, "Next attempt:", a.Status.NextAttemptAt.Local().Format(time.TimeOnly))
	}
	if command == "start" {
		fmt.Fprintln(out, "Start accepted. Use bimeron status or watch to follow connection.")
	}
	if command == "stop" {
		fmt.Fprintln(out, "Session disconnected. Daemon remains running.")
	}
	if command == "shutdown" {
		fmt.Fprintln(out, "Daemon shutdown accepted; session cleanup completed.")
	}
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
	return writeDaemonJSON(os.Stdout, a.Stats)
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
		if err != nil && a.Version == 0 && instance == "" {
			// No daemon was ever reached: report it instead of waiting forever.
			return err
		}
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
				fmt.Fprintln(out, "Some events were skipped; current state:", shown(a.Status.State))
			}
			for _, e := range a.Events {
				fmt.Fprintf(out, "%s [%s] %s\n", e.Event.Time.Format("15:04:05"), shown(e.Event.State), shown(e.Event.Message))
				if e.Event.LastError != "" {
					fmt.Fprintln(out, "Reason:", shown(e.Event.LastError))
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
