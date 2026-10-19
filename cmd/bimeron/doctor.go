package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"runtime/debug"
	"time"

	"bimeron/core"
	"bimeron/internal/control"
	"bimeron/internal/telemetry"
)

type diagnosticCheck struct {
	Name   string `json:"name"`
	Result string `json:"result"`
	Count  *int   `json:"count,omitempty"`
}
type diagnosticStatus struct {
	State     core.State `json:"state"`
	Attempt   int        `json:"attempt"`
	Since     time.Time  `json:"since"`
	LastError string     `json:"last_error,omitempty"`
}
type diagnosticEvent struct {
	Sequence uint64     `json:"sequence"`
	Time     time.Time  `json:"time"`
	State    core.State `json:"state"`
	Code     string     `json:"code"`
	Error    string     `json:"error,omitempty"`
}
type diagnosticReport struct {
	Core         *core.BuildDetails  `json:"core,omitempty"`
	Schema       int                 `json:"schema"`
	Time         time.Time           `json:"time"`
	Platform     string              `json:"platform"`
	Architecture string              `json:"architecture"`
	GoVersion    string              `json:"go_version"`
	CLIRevision  string              `json:"cli_revision,omitempty"`
	CLIModified  bool                `json:"cli_modified"`
	Protocol     int                 `json:"protocol"`
	Checks       []diagnosticCheck   `json:"checks"`
	Status       *diagnosticStatus   `json:"status,omitempty"`
	Stats        *telemetry.Snapshot `json:"stats,omitempty"`
	Capabilities core.Capabilities   `json:"capabilities"`
	Events       []diagnosticEvent   `json:"events,omitempty"`
}

var diagnosticCode = regexp.MustCompile(`^[a-z][a-z0-9_]{0,95}$`)

func safeDiagnosticCode(s string) string {
	if s == "" || diagnosticCode.MatchString(s) {
		return s
	}
	return "redacted_error"
}

func gatherDiagnostics(ctx context.Context, call func(context.Context, control.Request) (control.Response, error), host func(context.Context) []diagnosticCheck) diagnosticReport {
	r := diagnosticReport{Schema: 1, Time: time.Now().UTC(), Platform: runtime.GOOS, Architecture: runtime.GOARCH, GoVersion: runtime.Version(), Protocol: control.Version, Capabilities: core.PlatformCapabilities()}
	if b, ok := debug.ReadBuildInfo(); ok {
		for _, s := range b.Settings {
			if s.Key == "vcs.revision" {
				r.CLIRevision = s.Value
			}
			if s.Key == "vcs.modified" {
				r.CLIModified = s.Value == "true"
			}
		}
	}
	request := func(command string) (control.Response, error) {
		attempt, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		return call(attempt, control.Request{Command: command})
	}
	a, err := request("status")
	if err != nil {
		r.Checks = append(r.Checks, diagnosticCheck{Name: "local_control", Result: "unavailable"})
	} else {
		r.Checks = append(r.Checks, diagnosticCheck{Name: "local_control", Result: "available"})
		r.Status = &diagnosticStatus{State: a.Status.State, Attempt: a.Status.Attempt, Since: a.Status.Since, LastError: safeDiagnosticCode(a.Status.LastError)}
		instance := a.Instance
		hello, buildErr := request("hello")
		if buildErr == nil && hello.Instance == instance {
			r.Core = hello.Core
		}
		stats, e := request("stats")
		if e == nil && stats.Instance == instance {
			r.Stats = stats.Stats
		} else {
			r.Checks = append(r.Checks, diagnosticCheck{Name: "session_stats", Result: "unavailable_or_restarted"})
		}
		events, e := request("events")
		if e == nil && events.Instance == instance {
			entries := events.Events
			if len(entries) > 20 {
				entries = entries[len(entries)-20:]
			}
			for _, entry := range entries {
				r.Events = append(r.Events, diagnosticEvent{Sequence: entry.Sequence, Time: entry.Event.Time, State: entry.Event.State, Code: safeDiagnosticCode(entry.Event.Code), Error: safeDiagnosticCode(entry.Event.LastError)})
			}
		} else {
			r.Checks = append(r.Checks, diagnosticCheck{Name: "recent_events", Result: "unavailable_or_restarted"})
		}
	}
	r.Checks = append(r.Checks, host(ctx)...)
	return r
}
func doctor(args []string) error {
	f := flag.NewFlagSet("doctor", flag.ContinueOnError)
	output := f.String("output", "", "write a new JSON report file")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return fmt.Errorf("usage: bimeron doctor [-output report.json]")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	report := gatherDiagnostics(ctx, control.Call, hostDiagnostics)
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if *output != "" {
		file, err := os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return fmt.Errorf("cannot create new diagnostic report: %w", err)
		}
		_, err = file.Write(data)
		closeErr := file.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		fmt.Println("Diagnostic report saved. No keys, IP addresses or external requests included.")
		return nil
	}
	_, err = os.Stdout.Write(data)
	return err
}
