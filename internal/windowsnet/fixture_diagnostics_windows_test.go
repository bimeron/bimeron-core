//go:build windows

package windowsnet

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"
)

// Only fixed, allowlisted records reach failure messages. Never print child
// stdout, arbitrary stderr, configuration, environment, or command arguments.
const fixtureEntry = `[Console]::Error.WriteLine('diag:entry');
[Console]::Error.WriteLine('diag:bits='+([IntPtr]::Size*8));
foreach($h in @('System32','SysWOW64')) {
 if($PSHOME -eq ($env:SystemRoot+'\'+$h+'\WindowsPowerShell\v1.0')) { [Console]::Error.WriteLine('diag:PSHOME='+$h+'\WindowsPowerShell\v1.0') }
}
$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; trap { exit 1 };
`

func fixtureSource(c Config, body string) string {
	payload, _ := json.Marshal(c)
	return fixtureEntry + `[Console]::Error.WriteLine('diag:json-start');
$taskConfig = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('` + base64.StdEncoding.EncodeToString(payload) + `')) | ConvertFrom-Json;
[Console]::Error.WriteLine('diag:json-done');
[Console]::Error.WriteLine('diag:fixture');
` + body + "\n[Console]::Error.WriteLine('diag:done');"
}

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
	start := time.Now()
	out, err := cmd.Output()
	var records []string
	for _, line := range strings.Split(trace.buffer.String(), "\n") {
		line = strings.TrimSuffix(line, "\r")
		switch line {
		case "diag:entry", "diag:bits=32", "diag:bits=64", "diag:json-start", "diag:json-done", "diag:fixture", "diag:done",
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
	diagnostic := fmt.Sprintf("elapsed=%s context=%v process=%s records=[%s]", time.Since(start).Round(time.Millisecond), ctx.Err(), process, strings.Join(records, ","))
	return out, err, diagnostic
}

func TestFixtureDiagnosticsControlledCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd, err := PowerShellCommand(ctx, fixtureSource(Config{Name: "config-secret"}, `[Console]::Out.Write('stdout-secret'); [Console]::Error.WriteLine('stderr-secret'); while($true) { [Threading.Thread]::Sleep(100) }`))
	if err != nil {
		t.Fatal(err)
	}
	_, err, diagnostic := runFixture(ctx, cmd, cancel)
	if err == nil || ctx.Err() != context.Canceled {
		t.Fatalf("controlled cancellation failed: %s", diagnostic)
	}
	for _, want := range []string{"elapsed=", "context=context canceled", "process=exit=", "diag:entry", "diag:bits=", "diag:PSHOME=", "diag:json-start", "diag:json-done", "diag:fixture"} {
		if !strings.Contains(diagnostic, want) {
			t.Fatalf("missing %s: %s", want, diagnostic)
		}
	}
	if len(diagnostic) > 1024 || strings.Contains(diagnostic, "secret") || strings.Contains(diagnostic, "diag:done") {
		t.Fatalf("unsafe or misleading diagnostic: %s", diagnostic)
	}
	t.Log(diagnostic)
	// Exercise the cap even when arbitrary stderr precedes markers.
	trace := &fixtureTrace{}
	trace.Write(bytes.Repeat([]byte("secret"), 2000))
	trace.Write([]byte("\r\ndiag:done\r\n"))
	if trace.buffer.Len() != 4096 {
		t.Fatal("stderr capture is not bounded")
	}
}

func TestFixtureDiagnosticsSanitizesFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd, err := PowerShellCommand(ctx, fixtureSource(Config{Name: "config-secret"}, `[Console]::Out.Write('stdout-secret'); [Console]::Error.WriteLine(('stderr-secret'*1000)); throw 'exception-secret'`))
	if err != nil {
		t.Fatal(err)
	}
	out, err, diagnostic := runFixture(ctx, cmd, nil)
	if err == nil || !bytes.Contains(out, []byte("stdout-secret")) || !strings.Contains(diagnostic, "process=exit=1") || !strings.Contains(diagnostic, "diag:fixture") || strings.Contains(diagnostic, "secret") || len(diagnostic) > 1024 {
		t.Fatalf("failure diagnostic lost bounded sanitized evidence: %s", diagnostic)
	}
}
