package control

import (
	core "bimeron/core"
	"bimeron/internal/guard"
	"bimeron/internal/problem"
	"bimeron/internal/telemetry"
	"context"
	"errors"
	"net"
	"path/filepath"
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

func TestStartReportsConfigurationProblems(t *testing.T) {
	e := &fakeEngine{state: core.Disconnected, events: make(chan core.Event)}
	s := NewServer(e)
	s.load = func(string) (core.SessionConfig, error) {
		return core.SessionConfig{}, problem.New("interface_name_invalid", "bad name").In("Interface").At("Name").AtLine(7)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Serve(ctx, l)
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	callCtx, end := context.WithTimeout(context.Background(), 3*time.Second)
	defer end()
	path, _ := filepath.Abs("test.conf")
	a, err := exchange(callCtx, c, Request{Command: "start", Config: path})
	if err == nil || err.Error() != "invalid_configuration" || len(a.Problems) != 1 || a.Problems[0].Code != "interface_name_invalid" || a.Problems[0].Line != 7 {
		t.Fatalf("%+v", a)
	}
}

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

// abandonEngine records whether the session context was still live when the
// server marked the session abandoned.
type abandonEngine struct {
	fakeEngine
	marked, liveAtMark, stopped bool
}

func (e *abandonEngine) MarkAbandon() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.marked = true
	e.liveAtMark = e.session != nil && e.session.Err() == nil
}
func (e *abandonEngine) Stop(context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.stopped = true
	return nil
}

// scriptedListener hands out queued connections, then fails.
type scriptedListener struct {
	conns chan net.Conn
	fail  chan struct{}
}

func (l scriptedListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.fail:
		return nil, errors.New("broken pipe instance")
	}
}
func (scriptedListener) Close() error   { return nil }
func (scriptedListener) Addr() net.Addr { return &net.TCPAddr{} }

// A broken control listener is not a user's stop: the session is marked
// abandoned while its context is still live, so protection stays installed.
func TestListenerFailureAbandonsSessionBeforeCancel(t *testing.T) {
	e := &abandonEngine{fakeEngine: fakeEngine{state: core.Disconnected, events: make(chan core.Event)}}
	s := NewServer(e)
	s.load = func(string) (core.SessionConfig, error) { return core.SessionConfig{}, nil }
	l := scriptedListener{conns: make(chan net.Conn), fail: make(chan struct{})}
	done := make(chan error, 1)
	go func() { done <- s.Serve(context.Background(), l) }()
	client, server := net.Pipe()
	l.conns <- server
	path, _ := filepath.Abs("held.conf")
	ctx, end := context.WithTimeout(context.Background(), 3*time.Second)
	defer end()
	if _, err := exchange(ctx, client, Request{Command: "start", Config: path}); err != nil {
		t.Fatal(err)
	}
	client.Close()
	close(l.fail)
	if err := <-done; err == nil {
		t.Fatal("listener failure swallowed")
	}
	if !e.marked || !e.liveAtMark || !e.stopped {
		t.Fatal("session not abandoned before cancellation", e.marked, e.liveAtMark, e.stopped)
	}

	stopped := &abandonEngine{fakeEngine: fakeEngine{events: make(chan core.Event)}}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	failed := make(chan struct{})
	close(failed)
	if err := NewServer(stopped).Serve(cancelled, scriptedListener{conns: make(chan net.Conn), fail: failed}); err != nil {
		t.Fatal(err)
	}
	if stopped.marked || !stopped.stopped {
		t.Fatal("shutdown did not stop the session", stopped.marked, stopped.stopped)
	}
}

type panickingListener struct{ scriptedListener }

func (l panickingListener) Accept() (net.Conn, error) {
	c, err := l.scriptedListener.Accept()
	if err != nil {
		panic("accept")
	}
	return c, nil
}

func TestServeDispatchesListenerPanicBeforeSessionCancellation(t *testing.T) {
	e := &abandonEngine{fakeEngine: fakeEngine{state: core.Disconnected, events: make(chan core.Event)}}
	s := NewServer(e)
	s.load = func(string) (core.SessionConfig, error) { return core.SessionConfig{}, nil }
	l := panickingListener{scriptedListener{conns: make(chan net.Conn), fail: make(chan struct{})}}
	dispatched := false
	defer guard.Register(func(p any) <-chan struct{} {
		e.mu.Lock()
		dispatched = p == "accept" && !e.marked && !e.stopped && e.session != nil && e.session.Err() == nil
		e.mu.Unlock()
		done := make(chan struct{})
		close(done)
		return done
	})()
	result := make(chan any, 1)
	go func() {
		defer func() { result <- recover() }()
		_ = s.Serve(context.Background(), l)
	}()
	client, server := net.Pipe()
	l.conns <- server
	path, _ := filepath.Abs("held.conf")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := exchange(ctx, client, Request{Command: "start", Config: path})
	client.Close()
	close(l.fail)
	select {
	case p := <-result:
		// The session already ran its crash cleanup through the guard; a real
		// engine's Stop would wait for a run that never finishes.
		if err != nil || p != "accept" || !dispatched || e.marked || e.stopped {
			t.Fatalf("start=%v panic=%v live at dispatch=%v marked=%v stopped=%v", err, p, dispatched, e.marked, e.stopped)
		}
	case <-ctx.Done():
		t.Fatal("listener panic stalled")
	}
}

// configEngine records the configuration of the last Start.
type configEngine struct {
	fakeEngine
	started chan core.SessionConfig
}

func (e *configEngine) Start(ctx context.Context, c core.SessionConfig) error {
	e.started <- c
	return e.fakeEngine.Start(ctx, c)
}

// Sessions started through the daemon never use the daemon account's home
// keys or SSH agent, whatever the loaded configuration says.
func TestStartDisablesDaemonSSHFallbacks(t *testing.T) {
	e := &configEngine{fakeEngine: fakeEngine{state: core.Disconnected, events: make(chan core.Event)}, started: make(chan core.SessionConfig, 1)}
	s := NewServer(e)
	s.load = func(string) (core.SessionConfig, error) {
		c := core.DefaultConfig()
		c.SSHDefaultKeys = true
		return c, nil
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Serve(ctx, l)
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	callCtx, end := context.WithTimeout(context.Background(), 3*time.Second)
	defer end()
	path, _ := filepath.Abs("test.conf")
	if _, err := exchange(callCtx, c, Request{Command: "start", Config: path}); err != nil {
		t.Fatal(err)
	}
	cfg := <-e.started
	if cfg.SSHDefaultKeys || !cfg.SSHNoAgent || cfg.SSHPrompt == nil {
		t.Fatalf("daemon session SSH settings: default keys %t, no agent %t, prompt %t", cfg.SSHDefaultKeys, cfg.SSHNoAgent, cfg.SSHPrompt != nil)
	}
}
