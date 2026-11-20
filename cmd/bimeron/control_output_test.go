package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode"

	core "bimeron/core"
	"bimeron/internal/control"
	"bimeron/internal/displaytext"
)

// hostile holds ESC, OSC, CSI, BEL, BS, C1 CSI, an RLO override and CR LF.
var hostile = "\x1b]0;title\x07x\x1b[2J" + string(rune(0x9b)) + "31m" + string(rune(0x202E)) + "\r\nfake\b"

// requireDisplaySafe fails if out contains a control or bidirectional
// formatting character other than the line feeds that end lines, or a line
// that a daemon string started.
func requireDisplaySafe(t *testing.T, out string) {
	t.Helper()
	for _, r := range out {
		if r != '\n' && (unicode.IsControl(r) || r == 0x202E) {
			t.Fatalf("output keeps %U: %q", r, out)
		}
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "fake") {
			t.Fatalf("daemon text started a line: %q", out)
		}
	}
	if !strings.ContainsRune(out, displaytext.Replacement) || !strings.Contains(out, "title") {
		t.Fatalf("replaced characters are not visible: %q", out)
	}
}

func TestControlOutputFiltersDaemonText(t *testing.T) {
	a := control.Response{Version: control.Version, Status: core.Status{
		State:     core.State(hostile),
		LastError: hostile,
		Session: &core.SessionInfo{ID: hostile, ProfileID: hostile, ProfileName: hostile, Mode: hostile, IPv6: hostile,
			ServerTCP: hostile, ServerTCPName: hostile, ServerUDP: hostile, ServerUDPName: hostile},
	}}
	var out strings.Builder
	printControlResult(&out, "status", a)
	requireDisplaySafe(t, out.String())
	if got := strings.Count(out.String(), "\n"); got != 7 {
		t.Fatalf("status printed %d lines, want 7: %q", got, out.String())
	}
}

// JSON output keeps daemon text intact but escapes every terminal control.
func TestDaemonJSONEscapesControls(t *testing.T) {
	var out strings.Builder
	if err := writeDaemonJSON(&out, core.BuildDetails{Version: hostile}); err != nil {
		t.Fatal(err)
	}
	text := strings.TrimSuffix(out.String(), "\n")
	if strings.ContainsFunc(text, func(r rune) bool { return unicode.IsControl(r) || r == 0x202E }) {
		t.Fatalf("JSON output keeps a control character: %q", out.String())
	}
	var back core.BuildDetails
	if err := json.Unmarshal([]byte(text), &back); err != nil || back.Version != hostile {
		t.Fatalf("JSON output %q decodes to %q, %v", text, back.Version, err)
	}
}

func TestWatchOutputFiltersDaemonText(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	call := func(context.Context, control.Request) (control.Response, error) {
		if calls++; calls > 1 {
			cancel()
			return control.Response{Version: control.Version, Instance: "a"}, nil
		}
		return control.Response{Version: control.Version, Instance: "a", Dropped: true, Status: core.Status{State: core.State(hostile)},
			Events: []control.LoggedEvent{{Event: core.Event{State: core.State(hostile), Message: hostile, LastError: hostile}}}}, nil
	}
	var out strings.Builder
	if err := watchEvents(ctx, call, &out, watchTiming{poll: time.Millisecond, retryMin: time.Millisecond, retryMax: time.Millisecond}); err != nil {
		t.Fatal(err)
	}
	requireDisplaySafe(t, out.String())
	if got := strings.Count(out.String(), "\n"); got != 3 {
		t.Fatalf("watch printed %d lines, want 3: %q", got, out.String())
	}
}
