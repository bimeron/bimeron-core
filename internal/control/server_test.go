package control

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	core "bimeron/core"
	"bimeron/internal/telemetry"
	"sync"
	"testing"
	"time"
)

type fakeEngine struct {
	mu      sync.Mutex
	state   core.State
	session context.Context
	stopErr error
	events  chan core.Event
}

func (e *fakeEngine) Start(ctx context.Context, _ core.SessionConfig) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.session = ctx
	e.state = core.Connected
	return nil
}
func (e *fakeEngine) Stop(context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.stopErr != nil {
		return e.stopErr
	}
	e.state = core.Disconnected
	return nil
}
func (e *fakeEngine) Status() core.Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	return core.Status{State: e.state}
}
func (e *fakeEngine) Events() <-chan core.Event { return e.events }
func (e *fakeEngine) Stats() telemetry.Snapshot { return telemetry.Snapshot{} }

func TestStopKeepsDaemonAndShutdownExits(t *testing.T) {
	e := &fakeEngine{state: core.Disconnected, events: make(chan core.Event)}
	s := NewServer(e)
	s.load = func(string) (core.SessionConfig, error) { return core.SessionConfig{}, nil }
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, l) }()
	request := func(r Request) Response {
		t.Helper()
		c, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		callCtx, end := context.WithTimeout(context.Background(), time.Second*3)
		defer end()
		a, err := exchange(callCtx, c, r)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	path, _ := filepath.Abs("test.conf")
	request(Request{Command: "start", Config: path})
	e.mu.Lock()
	session := e.session
	e.mu.Unlock()
	if session.Err() != nil {
		t.Fatal("client exit cancelled VPN")
	}
	if a := request(Request{Command: "stop"}); a.Status.State != core.Disconnected {
		t.Fatal(a)
	}
	request(Request{Command: "status"})
	if a := request(Request{Command: "stats"}); a.Stats == nil {
		t.Fatal(a)
	}
	if a := request(Request{Command: "capabilities"}); a.Capabilities == nil || a.Capabilities.Platform == "" {
		t.Fatal(a)
	}
	request(Request{Command: "stop"}) // idempotent
	if a := request(Request{Command: "start", Config: path}); a.Status.State != core.Connected {
		t.Fatal(a)
	}
	request(Request{Command: "shutdown"})
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second * 3):
		t.Fatal("shutdown did not exit")
	}
	if session.Err() == nil {
		t.Fatal("daemon exit did not cancel session context")
	}
}

func TestFailedShutdownKeepsControlAvailable(t *testing.T) {
	e := &fakeEngine{stopErr: errors.New("cleanup_failed")}
	s := NewServer(e)
	a := s.dispatch(context.Background(), Request{Version: Version, Command: "shutdown"})
	if a.Error != "session_stop_failed" || s.closing {
		t.Fatal(a)
	}
}

func TestProtocolAndBoundedHistory(t *testing.T) {
	s := NewServer(&fakeEngine{})
	for i := 0; i < 140; i++ {
		s.record(core.Event{Code: "connected"})
	}
	a := s.dispatch(context.Background(), Request{Version: Version, Command: "events"})
	if len(a.Events) != 128 || !a.Dropped || a.Cursor != 140 {
		t.Fatal("history bounds", a)
	}
	for _, r := range []Request{{Version: 2, Command: "stop"}, {Version: Version, Command: "start", Config: "relative.conf"}, {Version: Version, Command: "stop", Config: "extra"}, {Version: Version, Command: "events", After: 141}, {Version: Version, Command: "invalid"}} {
		if s.dispatch(context.Background(), r).Error == "" {
			t.Fatal("accepted invalid request", r)
		}
	}
}
