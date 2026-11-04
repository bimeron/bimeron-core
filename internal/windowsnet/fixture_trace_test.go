package windowsnet

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

type fixtureTrace struct {
	buffer    bytes.Buffer
	onFixture func()
}

func (d *fixtureTrace) Write(p []byte) (int, error) {
	n := len(p)
	if left := 4096 - d.buffer.Len(); left > 0 {
		if len(p) > left {
			p = p[:left]
		}
		d.buffer.Write(p)
	}
	if d.onFixture != nil && (bytes.Contains(d.buffer.Bytes(), []byte("diag:fixture\r\n")) || bytes.Contains(d.buffer.Bytes(), []byte("diag:fixture\n"))) {
		d.onFixture()
		d.onFixture = nil
	}
	return n, nil
}

func runFixture(ctx context.Context, cmd *exec.Cmd, onFixture func()) ([]byte, error, string) {
	trace := &fixtureTrace{onFixture: onFixture}
	cmd.Stderr = trace
	// Bound inherited pipe handles after cancellation or process exit. This does
	// not extend the caller's execution deadline or change production commands.
	cmd.WaitDelay = 2 * time.Second
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	start := time.Now()
	err := cmd.Start()
	started := err == nil
	startElapsed := time.Since(start)
	if started {
		err = cmd.Wait()
	}
	out := stdout.Bytes()
	var records []string
	for _, line := range strings.Split(trace.buffer.String(), "\n") {
		line = strings.TrimSuffix(line, "\r")
		switch line {
		case "diag:entry", "diag:bits=32", "diag:bits=64", "diag:json-start", "diag:json-done", "diag:fixture", "diag:done", "diag:module-start", "diag:module-done",
			`diag:PSHOME=System32\WindowsPowerShell\v1.0`, `diag:PSHOME=SysWOW64\WindowsPowerShell\v1.0`,
			`diag:module=System32\WindowsPowerShell\v1.0\Modules\NetTCPIP`, `diag:module=SysWOW64\WindowsPowerShell\v1.0\Modules\NetTCPIP`:
			if !slices.Contains(records, line) {
				records = append(records, line)
			}
		}
	}
	process := "ok"
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			process = fmt.Sprintf("exit=%d", exit.ExitCode())
		} else {
			process = fmt.Sprintf("error-type=%T", err)
		}
	}
	phase := "process-start"
	if started {
		phase = "awaiting-script-entry"
	}
	if len(records) > 0 {
		phase = records[len(records)-1]
	}
	diagnostic := fmt.Sprintf("elapsed=%s started=%t start=%s wait=%s phase=%s pipe-timeout=%t context=%v process=%s records=[%s]", time.Since(start).Round(time.Millisecond), started, startElapsed.Round(time.Millisecond), (time.Since(start) - startElapsed).Round(time.Millisecond), phase, errors.Is(err, exec.ErrWaitDelay), ctx.Err(), process, strings.Join(records, ","))
	return out, err, diagnostic
}

// Reuse the test executable so diagnostic regressions run without PowerShell.
func TestFixtureTraceProcess(t *testing.T) {
	mode := os.Getenv("BIMERON_FIXTURE_TRACE_TEST")
	if mode == "" {
		return
	}
	if mode == "pipe-holder" {
		time.Sleep(4 * time.Second)
		os.Exit(0)
	}
	if mode == "inherited-pipe" {
		child := exec.Command(os.Args[0], "-test.run=^TestFixtureTraceProcess$")
		child.Env = append(os.Environ(), "BIMERON_FIXTURE_TRACE_TEST=pipe-holder")
		child.Stdout, child.Stderr = os.Stdout, os.Stderr
		if child.Start() != nil {
			os.Exit(2)
		}
		os.Exit(0)
	}
	fmt.Fprintln(os.Stderr, "diag:entry\ndiag:fixture")
	fmt.Fprint(os.Stdout, "stdout-secret")
	fmt.Fprintln(os.Stderr, "stderr-secret")
	if mode == "cancel" {
		time.Sleep(10 * time.Second)
	}
	os.Exit(1)
}

func TestFixtureTraceLifecycle(t *testing.T) {
	for _, mode := range []string{"failure", "cancel", "inherited-pipe", "start-failure"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestFixtureTraceProcess$")
			cmd.Env = append(os.Environ(), "BIMERON_FIXTURE_TRACE_TEST="+mode)
			if mode == "start-failure" {
				cmd.Path = filepath.Join(t.TempDir(), "missing")
			}
			var callback func()
			if mode == "cancel" {
				callback = cancel
			}
			out, err, diagnostic := runFixture(ctx, cmd, callback)
			if err == nil || strings.Contains(diagnostic, "secret") || len(diagnostic) > 1024 {
				t.Fatalf("unsafe failure: %s", diagnostic)
			}
			switch mode {
			case "failure":
				if string(out) != "stdout-secret" || !strings.Contains(diagnostic, "phase=diag:fixture") || !strings.Contains(diagnostic, "process=exit=1") {
					t.Fatal(diagnostic)
				}
			case "cancel":
				if ctx.Err() != context.Canceled || !strings.Contains(diagnostic, "diag:fixture") {
					t.Fatal(diagnostic)
				}
			case "inherited-pipe":
				if !errors.Is(err, exec.ErrWaitDelay) || !strings.Contains(diagnostic, "pipe-timeout=true") || ctx.Err() != nil {
					t.Fatal(diagnostic)
				}
			case "start-failure":
				if !strings.Contains(diagnostic, "started=false") || !strings.Contains(diagnostic, "phase=process-start") {
					t.Fatal(diagnostic)
				}
			}
		})
	}
}

func TestFixtureTraceSplitMarkerAndCap(t *testing.T) {
	calls := 0
	trace := &fixtureTrace{onFixture: func() { calls++ }}
	for _, chunk := range []string{"diag:fix", "ture\r", "\n", "diag:fixture\n"} {
		trace.Write([]byte(chunk))
	}
	trace.Write(bytes.Repeat([]byte("secret"), 2000))
	if calls != 1 || trace.buffer.Len() != 4096 {
		t.Fatalf("callback=%d capture=%d", calls, trace.buffer.Len())
	}
}
