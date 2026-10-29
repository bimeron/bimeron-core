package control

import (
	"bimeron/core"
	"bimeron/internal/systemvpn"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func lifecycleServer() (*Server, *countedForegroundEngine) {
	e := &countedForegroundEngine{fakeEngine: fakeEngine{state: core.Disconnected}}
	s := NewServer(e)
	s.build = func() core.BuildDetails { return core.BuildDetails{Revision: strings.Repeat("a", 40)} }
	s.bindForegroundSession(context.Background(), core.SessionConfig{})
	return s, e
}

type pausedOwnerConn struct {
	net.Conn
	writing chan struct{}
	release chan struct{}
	fail    bool
}

func (c *pausedOwnerConn) Write(p []byte) (int, error) {
	close(c.writing)
	<-c.release
	if c.fail {
		return 0, errors.New("write refused")
	}
	return c.Conn.Write(p)
}

func TestForegroundLifecyclePendingCloseResponseBlocksActivation(t *testing.T) {
	for _, mode := range []string{"normal", "write-failure", "oversized"} {
		t.Run(mode, func(t *testing.T) {
			s, e := lifecycleServer()
			if mode == "oversized" {
				e.mu.Lock()
				e.state = core.Disconnected
				e.mu.Unlock()
				original := s.foregroundDispatch
				s.foregroundDispatch = func(ctx context.Context, r Request) Response {
					a := original(ctx, r)
					a.Status.LastError = strings.Repeat("x", 300000)
					return a
				}
			}
			shutdown := make(chan struct{})
			s.shutdown = func() { close(shutdown) }
			server, client := net.Pipe()
			defer client.Close()
			c := &pausedOwnerConn{Conn: server, writing: make(chan struct{}), release: make(chan struct{}), fail: mode == "write-failure"}
			done := make(chan struct{})
			go func() { s.handle(context.Background(), c); close(done) }()
			client.SetDeadline(time.Now().Add(3 * time.Second))
			io.WriteString(client, `{"version":1,"id":"close","command":"close_owner","instance":"`+s.instance+`"}`+"\n")
			<-c.writing
			r := ownerRequest(s, "hello")
			r.AcceptRevision = strings.Repeat("a", 40)
			a := s.foregroundDispatch(context.Background(), r)
			if a.Error != "owner_closing" || e.starts.Load() != 0 {
				t.Errorf("error=%q starts=%d", a.Error, e.starts.Load())
			}
			select {
			case <-shutdown:
				t.Error("shutdown before write attempt completed")
			default:
			}
			close(c.release)
			if !c.fail {
				var response Response
				if err := json.NewDecoder(client).Decode(&response); err != nil {
					t.Fatal(err)
				}
				if mode == "oversized" && response.Error != "response_too_large" {
					t.Fatal(response)
				}
			}
			<-done
			select {
			case <-shutdown:
			default:
				t.Fatal("accepted close lost shutdown")
			}
		})
	}
}

func ownerRequest(s *Server, command string) Request {
	return Request{Version: Version, ID: "test", Instance: s.instance, Command: command}
}

func TestForegroundLifecycleCloseAndStopBeforeActivation(t *testing.T) {
	for _, command := range []string{"close_owner", "stop"} {
		t.Run(command, func(t *testing.T) {
			s, e := lifecycleServer()
			if a := s.foregroundDispatch(context.Background(), ownerRequest(s, command)); a.Error != "" {
				t.Fatal(a)
			}
			r := ownerRequest(s, "hello")
			r.AcceptRevision = strings.Repeat("a", 40)
			a := s.foregroundDispatch(context.Background(), r)
			expected := "owner_closing"
			if command == "stop" {
				expected = "activation_cancelled"
			}
			if a.Error != expected || e.starts.Load() != 0 {
				t.Fatalf("error=%q starts=%d", a.Error, e.starts.Load())
			}
		})
	}
}

func TestProfileControlCloseCommitsAdmission(t *testing.T) {
	s := NewServer(&fakeEngine{})
	s.build = func() core.BuildDetails { return core.BuildDetails{Revision: strings.Repeat("a", 40)} }
	wait := s.bindProfileControl(systemvpn.Config{}, false, func(systemvpn.Config) (systemvpn.ProfilePlan, error) {
		return systemvpn.ProfilePlan{StateToken: "token"}, nil
	}, func(systemvpn.Config, bool, string) (systemvpn.ProfilePlan, error) {
		t.Error("apply after close")
		return systemvpn.ProfilePlan{}, nil
	})
	s.foregroundDispatch(context.Background(), Request{Version: Version, ID: "h", Command: "hello"})
	wait()
	if a := s.foregroundDispatch(context.Background(), ownerRequest(s, "close_owner")); a.Error != "" {
		t.Fatal(a)
	}
	r := ownerRequest(s, "apply")
	r.AcceptRevision = strings.Repeat("a", 40)
	r.PlanToken = "token"
	if a := s.foregroundDispatch(context.Background(), r); a.Error != "owner_closing" {
		t.Fatal(a)
	}
	wait()
}

type blockingLaunchEngine struct {
	fakeEngine
	entered, release chan struct{}
}

func (e *blockingLaunchEngine) Start(ctx context.Context, cfg core.SessionConfig) error {
	close(e.entered)
	<-e.release
	return e.fakeEngine.Start(ctx, cfg)
}

func TestForegroundLifecycleActivationFirstRefusesCloseAndRemainsUsable(t *testing.T) {
	e := &blockingLaunchEngine{entered: make(chan struct{}), release: make(chan struct{})}
	s := NewServer(e)
	s.build = func() core.BuildDetails { return core.BuildDetails{Revision: strings.Repeat("a", 40)} }
	s.bindForegroundSession(context.Background(), core.SessionConfig{})
	activated := make(chan Response, 1)
	r := ownerRequest(s, "hello")
	r.AcceptRevision = strings.Repeat("a", 40)
	go func() { activated <- s.foregroundDispatch(context.Background(), r) }()
	<-e.entered
	closed := make(chan Response, 1)
	go func() { closed <- s.foregroundDispatch(context.Background(), ownerRequest(s, "close_owner")) }()
	close(e.release)
	if a := <-activated; a.Error != "" {
		t.Fatal(a)
	}
	if a := <-closed; a.Error != "session_not_terminal" {
		t.Fatal(a)
	}
	if a := s.foregroundDispatch(context.Background(), ownerRequest(s, "status")); a.Error != "" {
		t.Fatal(a)
	}
	if a := s.foregroundDispatch(context.Background(), ownerRequest(s, "stop")); a.Error != "" {
		t.Fatal(a)
	}
	if a := s.foregroundDispatch(context.Background(), ownerRequest(s, "close_owner")); a.Error != "" {
		t.Fatal(a)
	}
}

func TestForegroundLifecycleInvalidRequestsDoNotTransition(t *testing.T) {
	for _, command := range []string{"stop", "close_owner", "hello"} {
		for _, mutate := range []func(*Request){func(r *Request) { r.ID = "" }, func(r *Request) { r.Instance = "stale" }, func(r *Request) { r.Session = "stale" }, func(r *Request) { r.After = 1 }, func(r *Request) { r.Version = 99 }, func(r *Request) { r.Installation = "foreign" }, func(r *Request) { r.PlanToken = "unexpected" }} {
			s, e := lifecycleServer()
			r := ownerRequest(s, command)
			if command == "hello" {
				r.AcceptRevision = strings.Repeat("a", 40)
			}
			mutate(&r)
			if a := s.foregroundDispatch(context.Background(), r); a.Error == "" {
				t.Fatalf("accepted malformed %s", command)
			}
			r = ownerRequest(s, "hello")
			r.AcceptRevision = strings.Repeat("a", 40)
			if a := s.foregroundDispatch(context.Background(), r); a.Error != "" || e.starts.Load() != 1 {
				t.Fatalf("invalid %s changed admission: %+v", command, a)
			}
		}
	}
}

func TestProfileControlApplyFirstRefusesCloseAndDrains(t *testing.T) {
	for _, remove := range []bool{false, true} {
		s := NewServer(&fakeEngine{})
		s.build = func() core.BuildDetails { return core.BuildDetails{Revision: strings.Repeat("a", 40)} }
		entered, release := make(chan struct{}), make(chan struct{})
		var once sync.Once
		unblock := func() { once.Do(func() { close(release) }) }
		defer unblock()
		wait := s.bindProfileControl(systemvpn.Config{}, remove, func(systemvpn.Config) (systemvpn.ProfilePlan, error) {
			return systemvpn.ProfilePlan{StateToken: "token", Action: "unchanged"}, nil
		}, func(systemvpn.Config, bool, string) (systemvpn.ProfilePlan, error) {
			close(entered)
			<-release
			return systemvpn.ProfilePlan{}, nil
		})
		s.foregroundDispatch(context.Background(), Request{Version: Version, ID: "hello", Command: "hello"})
		wait()
		command := "apply"
		if remove {
			command = "remove"
		}
		r := ownerRequest(s, command)
		r.PlanToken = "token"
		r.AcceptRevision = strings.Repeat("a", 40)
		bad := r
		bad.Instance = "stale"
		if a := s.foregroundDispatch(context.Background(), bad); a.Error != "stale_instance" {
			t.Fatal(a)
		}
		if a := s.foregroundDispatch(context.Background(), r); a.Error != "" {
			t.Fatal(a)
		}
		<-entered
		if a := s.foregroundDispatch(context.Background(), ownerRequest(s, "close_owner")); a.Error != "operation_pending" {
			t.Fatal(a)
		}
		drained := make(chan struct{})
		go func() { wait(); close(drained) }()
		select {
		case <-drained:
			t.Fatal("did not drain transaction")
		default:
		}
		if a := s.foregroundDispatch(context.Background(), ownerRequest(s, "status")); a.Operation != "applying" {
			t.Fatal(a)
		}
		unblock()
		<-drained
		if a := s.foregroundDispatch(context.Background(), ownerRequest(s, "close_owner")); a.Error != "" {
			t.Fatal(a)
		}
	}
}

func TestProfileControlPendingCloseResponseBlocksApply(t *testing.T) {
	s := NewServer(&fakeEngine{})
	s.build = func() core.BuildDetails { return core.BuildDetails{Revision: strings.Repeat("a", 40)} }
	wait := s.bindProfileControl(systemvpn.Config{}, false, func(systemvpn.Config) (systemvpn.ProfilePlan, error) {
		return systemvpn.ProfilePlan{StateToken: "token"}, nil
	}, func(systemvpn.Config, bool, string) (systemvpn.ProfilePlan, error) {
		t.Error("apply admitted during close write")
		return systemvpn.ProfilePlan{}, nil
	})
	s.foregroundDispatch(context.Background(), Request{Version: Version, ID: "hello", Command: "hello"})
	wait()
	server, client := net.Pipe()
	defer client.Close()
	c := &pausedOwnerConn{Conn: server, writing: make(chan struct{}), release: make(chan struct{}), fail: true}
	done := make(chan struct{})
	go func() { s.handle(context.Background(), c); close(done) }()
	client.SetDeadline(time.Now().Add(3 * time.Second))
	io.WriteString(client, `{"version":1,"id":"close","command":"close_owner","instance":"`+s.instance+`"}`+"\n")
	<-c.writing
	r := ownerRequest(s, "apply")
	r.AcceptRevision = strings.Repeat("a", 40)
	r.PlanToken = "token"
	if a := s.foregroundDispatch(context.Background(), r); a.Error != "owner_closing" {
		t.Error(a)
	}
	close(c.release)
	<-done
	wait()
}

type pausedStopEngine struct {
	fakeEngine
	entered, release chan struct{}
}

func (e *pausedStopEngine) Stop(context.Context) error { close(e.entered); <-e.release; return nil }
func TestForegroundLifecycleStopWaitDoesNotHoldAdmission(t *testing.T) {
	e := &pausedStopEngine{fakeEngine: fakeEngine{state: core.Disconnected}, entered: make(chan struct{}), release: make(chan struct{})}
	s := NewServer(e)
	s.bindForegroundSession(context.Background(), core.SessionConfig{})
	stopped := make(chan struct{})
	go func() { s.foregroundDispatch(context.Background(), ownerRequest(s, "stop")); close(stopped) }()
	<-e.entered
	status := make(chan Response, 1)
	go func() { status <- s.foregroundDispatch(context.Background(), ownerRequest(s, "status")) }()
	select {
	case a := <-status:
		if a.Error != "" {
			t.Error(a)
		}
	case <-time.After(time.Second):
		t.Error("Stop held admission lock")
	}
	close(e.release)
	<-stopped
}

type terminalActivityEngine struct {
	fakeEngine
	active bool
}

func (e *terminalActivityEngine) Status() core.Status {
	return core.Status{State: core.Failed, Session: &core.SessionInfo{ID: "session", Active: e.active}}
}
func TestForegroundLifecycleTerminalStateRequiresInactiveSession(t *testing.T) {
	e := &terminalActivityEngine{active: true}
	s := NewServer(e)
	s.bindForegroundSession(context.Background(), core.SessionConfig{})
	r := ownerRequest(s, "close_owner")
	r.Session = "session"
	if a := s.foregroundDispatch(context.Background(), r); a.Error != "session_not_terminal" || a.closeAccepted {
		t.Fatal(a)
	}
	e.active = false
	if a := s.foregroundDispatch(context.Background(), r); a.Error != "" || !a.closeAccepted {
		t.Fatal(a)
	}
}

func TestProfileControlInvalidCloseLeavesPreviewUsable(t *testing.T) {
	s := NewServer(&fakeEngine{})
	wait := s.bindProfileControl(systemvpn.Config{}, false, func(systemvpn.Config) (systemvpn.ProfilePlan, error) { return systemvpn.ProfilePlan{}, nil }, nil)
	for _, mutate := range []func(*Request){func(r *Request) { r.Instance = "stale" }, func(r *Request) { r.ID = "" }, func(r *Request) { r.After = 1 }, func(r *Request) { r.PlanToken = "unexpected" }, func(r *Request) { r.AcceptRevision = "unexpected" }, func(r *Request) { r.Installation = "foreign" }} {
		r := ownerRequest(s, "close_owner")
		mutate(&r)
		if a := s.foregroundDispatch(context.Background(), r); a.Error == "" || a.closeAccepted {
			t.Fatal(a)
		}
	}
	if a := s.foregroundDispatch(context.Background(), Request{Version: Version, ID: "h", Command: "hello"}); a.Error != "" {
		t.Fatal(a)
	}
	wait()
	if a := s.foregroundDispatch(context.Background(), ownerRequest(s, "close_owner")); a.Error != "" {
		t.Fatal(a)
	}
	if a := s.foregroundDispatch(context.Background(), Request{Version: Version, ID: "h", Command: "hello"}); a.Error != "owner_closing" {
		t.Fatal(a)
	}
}
