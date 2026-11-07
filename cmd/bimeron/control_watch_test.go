package main

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	core "bimeron/core"
	"bimeron/internal/control"
)

func TestWatchEventsSurvivesDaemonRestart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	unavailable := errors.New("local control unavailable")
	event := func(message string) []control.LoggedEvent {
		return []control.LoggedEvent{{Event: core.Event{Message: message}}}
	}
	var cursors []uint64
	steps := []func() (control.Response, error){
		func() (control.Response, error) { return control.Response{}, unavailable },
		func() (control.Response, error) {
			return control.Response{Version: 1, Instance: "a", Events: event("first"), Cursor: 3}, nil
		},
		func() (control.Response, error) { return control.Response{}, unavailable },
		func() (control.Response, error) { return control.Response{}, unavailable },
		func() (control.Response, error) {
			return control.Response{Version: 1, Instance: "b", Error: "cursor"}, errors.New("cursor")
		},
		func() (control.Response, error) {
			cancel()
			return control.Response{Version: 1, Instance: "b", Events: event("second"), Cursor: 1}, nil
		},
	}
	call := func(_ context.Context, r control.Request) (control.Response, error) {
		cursors = append(cursors, r.After)
		if len(cursors) > len(steps) {
			t.Fatal("watch kept polling after cancellation")
		}
		return steps[len(cursors)-1]()
	}
	var out strings.Builder
	timing := watchTiming{poll: time.Millisecond, retryMin: time.Millisecond, retryMax: 2 * time.Millisecond}
	if err := watchEvents(ctx, call, &out, timing); err != nil {
		t.Fatal("watch ended on an unavailable daemon:", err)
	}
	if got, want := cursors, []uint64{0, 0, 3, 3, 3, 0}; !slices.Equal(got, want) {
		t.Fatalf("cursors %v, want %v", got, want)
	}
	for _, want := range []string{"Daemon unavailable", "first", "Daemon restarted; resetting event cursor."} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("output %q misses %q", out.String(), want)
		}
	}
}

func TestWatchEventsReturnsDaemonErrors(t *testing.T) {
	daemonErr := errors.New("unsupported daemon protocol")
	call := func(context.Context, control.Request) (control.Response, error) {
		return control.Response{Version: 99}, daemonErr
	}
	if err := watchEvents(context.Background(), call, &strings.Builder{}, defaultWatchTiming); !errors.Is(err, daemonErr) {
		t.Fatal("daemon error was not returned:", err)
	}
}
