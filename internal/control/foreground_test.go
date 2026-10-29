package control

import (
	"bimeron/core"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestForegroundCommandsAndInstanceBinding(t *testing.T) {
	e := &fakeEngine{state: core.Disconnected}
	s := NewServer(e)
	s.foreground = true
	hello := s.foregroundDispatcher(context.Background(), Request{ID: "h", Version: 1, Command: "hello"})
	if hello.Error != "" || hello.Core == nil || hello.Capabilities == nil {
		t.Fatal(hello)
	}
	for _, command := range []string{"start", "shutdown", "stats", "auth_reply", "recover", "apply"} {
		a := s.foregroundDispatcher(context.Background(), Request{ID: "x", Version: 1, Command: command, Instance: s.instance})
		if a.Error != "unknown_command" {
			t.Fatalf("%s: %s", command, a.Error)
		}
	}
	a := s.foregroundDispatcher(context.Background(), Request{ID: "x", Version: 1, Command: "stop", Instance: "stale"})
	if a.Error != "stale_instance" {
		t.Fatal(a)
	}
	for i := 0; i < 130; i++ {
		s.record(core.Event{Code: "state"})
	}
	a = s.foregroundDispatcher(context.Background(), Request{ID: "e", Version: 1, Command: "events", Instance: s.instance})
	if !a.Dropped || len(a.Events) != 128 || a.Cursor != 130 {
		t.Fatal(a)
	}
	e.stopErr = errors.New("private-secret-sentinel")
	a = s.foregroundDispatcher(context.Background(), Request{ID: "s", Version: 1, Command: "stop", Instance: s.instance})
	if a.Error != "session_stop_failed" || strings.Contains(a.Error, "sentinel") {
		t.Fatal(a)
	}
}

type countedForegroundEngine struct {
	fakeEngine
	starts atomic.Int32
}

func (e *countedForegroundEngine) Start(ctx context.Context, cfg core.SessionConfig) error {
	e.starts.Add(1)
	return e.fakeEngine.Start(ctx, cfg)
}

func TestForegroundLaunchOnceAndClientLossDoesNotCancelOwner(t *testing.T) {
	owner, cancelOwner := context.WithCancel(context.Background())
	defer cancelOwner()
	e := &countedForegroundEngine{}
	s := NewServer(e)
	s.build = func() core.BuildDetails { return core.BuildDetails{Revision: strings.Repeat("a", 40)} }
	s.foreground = true
	s.bindForegroundSession(owner, core.SessionConfig{})
	client, cancelClient := context.WithCancel(context.Background())
	s.foregroundDispatch(client, Request{Version: 1, ID: "probe", Command: "hello"})
	if e.starts.Load() != 0 {
		t.Fatal("discovery started networking")
	}
	for i := 0; i < 3; i++ {
		s.foregroundDispatch(client, Request{Version: 1, ID: "hello", Command: "hello", Instance: s.instance, AcceptRevision: strings.Repeat("a", 40)})
	}
	cancelClient()
	if e.starts.Load() != 1 || e.session.Err() != nil {
		t.Fatal("duplicate start or client-owned session")
	}
	s.foregroundDispatch(owner, Request{Version: 1, ID: "x", Command: "start", Instance: s.instance})
	if e.starts.Load() != 1 {
		t.Fatal("IPC start accepted")
	}
}

func TestForegroundActivationRequiresReviewedUnmodifiedRevision(t *testing.T) {
	for _, build := range []core.BuildDetails{{Revision: strings.Repeat("a", 40), Modified: true}, {Revision: ""}, {Revision: strings.Repeat("b", 40)}} {
		e := &countedForegroundEngine{}
		s := NewServer(e)
		s.build = func() core.BuildDetails { return build }
		s.bindForegroundSession(context.Background(), core.SessionConfig{})
		a := s.foregroundDispatch(context.Background(), Request{Version: 1, ID: "activate", Command: "hello", Instance: s.instance, AcceptRevision: strings.Repeat("a", 40)})
		if a.Error != "core_identity_mismatch" || e.starts.Load() != 0 {
			t.Fatal("unreviewed revision mutated session")
		}
	}
}

type waitingForegroundEngine struct{ fakeEngine }

func (e *waitingForegroundEngine) Stop(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }

func TestForegroundStopTimeoutDoesNotRestartOrCloseOwner(t *testing.T) {
	e := &waitingForegroundEngine{fakeEngine: fakeEngine{state: core.Connecting}}
	s := NewServer(e)
	s.foreground = true
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	a := s.foregroundDispatcher(ctx, Request{Version: 1, ID: "s", Command: "stop", Instance: s.instance})
	if a.Error != "cleanup_pending" {
		t.Fatal(a)
	}
	if a = s.foregroundDispatcher(context.Background(), Request{Version: 1, ID: "c", Command: "close_owner", Instance: s.instance}); a.Error != "session_not_terminal" {
		t.Fatal(a)
	}
}

type foregroundFailureListener struct{ accepted chan struct{} }

func (l foregroundFailureListener) Accept() (net.Conn, error) {
	close(l.accepted)
	return nil, errors.New("broken IPC")
}
func (l foregroundFailureListener) Close() error   { return nil }
func (l foregroundFailureListener) Addr() net.Addr { return &net.TCPAddr{} }

type stopCountForegroundEngine struct {
	fakeEngine
	stops atomic.Int32
}

func (e *stopCountForegroundEngine) Stop(ctx context.Context) error {
	e.stops.Add(1)
	return e.fakeEngine.Stop(ctx)
}

func TestForegroundListenerLossDoesNotDisconnect(t *testing.T) {
	e := &stopCountForegroundEngine{fakeEngine: fakeEngine{events: make(chan core.Event)}}
	s := NewServer(e)
	s.foreground = true
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	listener := foregroundFailureListener{accepted: make(chan struct{})}
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, listener) }()
	<-listener.accepted
	select {
	case <-done:
		t.Fatal("IPC loss terminated owner")
	case <-time.After(10 * time.Millisecond):
	}
	if e.stops.Load() != 0 {
		t.Fatal("IPC loss stopped Engine")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("explicit owner cancellation stuck")
	}
	if e.stops.Load() != 1 {
		t.Fatal("explicit cancellation did not wait for cleanup")
	}
}

func TestForegroundDeniedPeerAndMalformedFramesCannotDispatch(t *testing.T) {
	for _, raw := range []string{"{\"version\":1,\"id\":\"a\",\"command\":\"hello\",\"command\":\"stop\"}\n", strings.Repeat("x", maxRequest+1)} {
		e := &fakeEngine{}
		s := NewServer(e)
		s.foreground = true
		s.foreground = true
		s.foregroundDispatch = func(context.Context, Request) Response { t.Error("malformed request dispatched"); return Response{} }
		server, client := net.Pipe()
		done := make(chan struct{})
		go func() { s.handle(context.Background(), server); close(done) }()
		client.SetDeadline(time.Now().Add(time.Second))
		io.WriteString(client, raw)
		client.Close()
		<-done
	}
	e := &fakeEngine{}
	s := NewServer(e)
	s.foreground = true
	s.authorize = func(net.Conn) (func(), error) { return nil, errors.New("wrong peer") }
	server, client := net.Pipe()
	defer client.Close()
	s.handle(context.Background(), server)
}

type benchmarkForegroundEngine struct{ fakeEngine }

func (*benchmarkForegroundEngine) Status() core.Status {
	return core.Status{State: core.Connected, Session: &core.SessionInfo{ID: "native-session", Active: true, Backend: "ikev2", StatsUnavailable: true}, Native: &core.NativeStatus{Requested: true, WFP: "active", DNS: "active"}}
}

// Measures bounded JSON/control dispatch, not Windows authentication or RAS.
func BenchmarkForegroundStatus(b *testing.B) {
	s := NewServer(&benchmarkForegroundEngine{})
	s.foreground = true
	frame, _ := json.Marshal(Request{Version: 1, ID: "status", Command: "status", Instance: s.instance, Session: "native-session"})
	b.ReportAllocs()
	for b.Loop() {
		var r Request
		if json.Unmarshal(frame, &r) != nil {
			b.Fatal("invalid fixture")
		}
		answer := s.foregroundDispatcher(context.Background(), r)
		if _, err := json.Marshal(answer); err != nil {
			b.Fatal(err)
		}
	}
}

func TestForegroundRejectsAmbiguousJSON(t *testing.T) {
	for _, raw := range []string{`{"id":"a","id":"b"}`, `{"command":"hello","Command":"stop"}`, `{"command":"hello"} {}`, `[]`, "{\"id\":\"\xff\"}", `{"id":`} {
		if strictForegroundJSON([]byte(raw)) {
			t.Fatalf("accepted %q", raw)
		}
	}
	if !strictForegroundJSON([]byte("{\"id\":\"a\",\"version\":1,\"command\":\"hello\"}\n")) {
		t.Fatal("valid frame rejected")
	}
}

func TestForegroundPeerRejectsForeignAndReplacedIdentity(t *testing.T) {
	owner := ProcessIdentity{SID: "owner", Session: 1}
	expected := ProcessIdentity{SID: "owner", Session: 1, ImageSHA256: "reviewed", ImageVolume: 1, ImageIndex: 2}
	if !matchingForegroundPeer(owner, expected, expected) {
		t.Fatal("expected peer refused")
	}
	for _, change := range []func(*ProcessIdentity){func(p *ProcessIdentity) { p.SID = "foreign" }, func(p *ProcessIdentity) { p.Session = 2 }, func(p *ProcessIdentity) { p.ImageSHA256 = "spoof" }, func(p *ProcessIdentity) { p.ImageIndex = 3 }} {
		peer := expected
		change(&peer)
		if matchingForegroundPeer(owner, expected, peer) {
			t.Fatal("foreign peer accepted")
		}
	}
}

func TestDaemonRejectsPrivateForegroundBindings(t *testing.T) {
	s := NewServer(&fakeEngine{})
	for _, r := range []Request{{Version: 1, Command: "start", Instance: "private"}, {Version: 1, Command: "stop", PlanToken: "private"}} {
		if a := s.dispatch(context.Background(), r); a.Error != "invalid_request" {
			t.Fatal(a)
		}
	}
}

func TestForegroundResponseBoundDoesNotLeakDiagnosticText(t *testing.T) {
	s := NewServer(&fakeEngine{})
	s.foreground = true
	s.foregroundDispatch = func(context.Context, Request) Response {
		return Response{Status: core.Status{LastError: strings.Repeat("secret-sentinel", 30000)}}
	}
	server, client := net.Pipe()
	defer client.Close()
	go s.handle(context.Background(), server)
	client.SetDeadline(time.Now().Add(time.Second))
	io.WriteString(client, "{\"version\":1,\"id\":\"x\",\"command\":\"hello\"}\n")
	var answer Response
	if err := json.NewDecoder(client).Decode(&answer); err != nil {
		t.Fatal(err)
	}
	if answer.Error != "response_too_large" || answer.Status.LastError != "" {
		t.Fatal("unbounded diagnostic exposed")
	}
}
