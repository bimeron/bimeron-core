//go:build windows

package windowsnet

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"reflect"
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

func TestFixtureDiagnosticsControlledCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	// Cancellation readiness must not depend on JSON cmdlet/module initialization.
	// The shadow cmdlet makes an accidental parsing dependency fail on Windows.
	source := fixtureEntry + `function ConvertFrom-Json { throw 'unexpected-json-secret' }
[Console]::Error.WriteLine('diag:fixture');
[Console]::Out.Write('stdout-secret'); [Console]::Error.WriteLine('stderr-secret');
while($true) { [Threading.Thread]::Sleep(100) }
[Console]::Error.WriteLine('diag:done');`
	cmd, err := PowerShellCommand(ctx, source)
	if err != nil {
		t.Fatal(err)
	}
	_, err, diagnostic := runFixture(ctx, cmd, cancel)
	if err == nil || ctx.Err() != context.Canceled || cmd.ProcessState == nil {
		t.Fatalf("controlled cancellation failed: %s", diagnostic)
	}
	for _, want := range []string{"elapsed=", "context=context canceled", "process=exit=", "diag:entry", "diag:bits=", "diag:PSHOME=", "diag:fixture"} {
		if !strings.Contains(diagnostic, want) {
			t.Fatalf("missing %s: %s", want, diagnostic)
		}
	}
	if len(diagnostic) > 1024 || strings.Contains(diagnostic, "secret") || strings.Contains(diagnostic, "diag:done") || strings.Contains(diagnostic, "diag:json-") {
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
	if err == nil || !bytes.Contains(out, []byte("stdout-secret")) || !strings.Contains(diagnostic, "process=exit=1") || !strings.Contains(diagnostic, "diag:fixture") || !strings.Contains(diagnostic, "diag:json-done") || strings.Contains(diagnostic, "secret") || len(diagnostic) > 1024 {
		t.Fatalf("failure diagnostic lost bounded sanitized evidence: %s", diagnostic)
	}
}

func TestFixtureConfigJSONRoundTrip(t *testing.T) {
	want := Config{Action: "setup", MTU: 1400, DNS: []string{"1.1.1.1", "2606:4700:4700::1111"}, Name: "quoted-'\"-`-$()-雪\nsecret", Tag: "BimeronCore:roundtrip", Index: 42}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd, err := PowerShellCommand(ctx, fixtureSource(want, `$taskConfig | ConvertTo-Json -Compress`))
	if err != nil {
		t.Fatal(err)
	}
	out, err, diagnostic := runFixture(ctx, cmd, nil)
	if err != nil || ctx.Err() != nil || !strings.Contains(diagnostic, "diag:json-done") || !strings.Contains(diagnostic, "diag:done") {
		t.Fatalf("config round trip failed: %s", diagnostic)
	}
	var got Config
	if json.Unmarshal(out, &got) != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("config round trip changed input: %s", diagnostic)
	}
}
