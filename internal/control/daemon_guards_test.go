package control

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	core "bimeron/core"
)

// guardEngine models retained inactive identities without opening a tunnel.
type guardEngine struct {
	fakeEngine
	info          *core.SessionInfo
	starts, stops int
}

func (e *guardEngine) Start(context.Context, core.SessionConfig) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.starts++
	e.info = &core.SessionInfo{ID: fmt.Sprint(e.starts), Active: true}
	e.state = core.Connected
	return nil
}
func (e *guardEngine) Stop(context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.stops++
	if e.info != nil {
		e.info.Active = false
	}
	e.state = core.Disconnected
	return nil
}
func (e *guardEngine) Status() core.Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	s := core.Status{State: e.state}
	if e.info != nil {
		copy := *e.info
		s.Session = &copy
	}
	return s
}
func guardServer() (*Server, *guardEngine) {
	e := &guardEngine{}
	s := NewServer(e)
	s.load = func(string) (core.SessionConfig, error) { return core.SessionConfig{}, nil }
	return s, e
}
func TestDaemonSessionGuards(t *testing.T) {
	s, e := guardServer()
	path, _ := filepath.Abs("unused.conf")
	call := func(command, instance, session string) Response {
		r := Request{Version: Version, Command: command, Instance: instance, Session: session}
		if command == "start" {
			r.Config = path
		}
		return s.dispatch(context.Background(), r)
	}
	check := func(a Response, want string) {
		t.Helper()
		if a.Error != want || a.Instance != s.instance {
			t.Fatalf("got %+v, want %q", a, want)
		}
	}
	check(call("start", "old", ""), "stale_instance")
	if e.starts != 0 {
		t.Fatal("stale start mutated engine")
	}
	check(call("start", s.instance, ""), "")
	check(call("start", s.instance, ""), "session_already_running")
	check(call("stop", "old", "1"), "stale_instance")
	check(call("stop", s.instance, "old"), "stale_session")
	if e.stops != 0 || e.starts != 1 {
		t.Fatal("rejected command mutated engine")
	}
	check(call("stop", s.instance, "1"), "")
	check(call("stop", s.instance, "1"), "stale_session")
	check(call("start", s.instance, ""), "")
	a := call("stop", s.instance, "1")
	check(a, "stale_session")
	if a.Status.Session == nil || a.Status.Session.ID != "2" || !a.Status.Session.Active || e.stops != 1 {
		t.Fatalf("missing authoritative status: %+v", a)
	}
	for _, r := range []Request{
		{Command: "stop", Session: "2"}, {Command: "stop", Instance: s.instance},
		{Command: "start", Instance: s.instance, Session: "2", Config: path},
		{Command: "shutdown", Instance: s.instance, Session: "2"},
		{Command: "status", Instance: s.instance},
	} {
		r.Version = Version
		check(s.dispatch(context.Background(), r), "invalid_request")
	}
	check(call("stop", "", ""), "") // Legacy stop remains unguarded and idempotent.
	check(call("stop", "", ""), "")
	check(call("shutdown", "", ""), "")
	check(call("start", s.instance, ""), "daemon_shutting_down")
}

func TestDaemonConcurrentGuardAdmission(t *testing.T) {
	s, e := guardServer()
	path, _ := filepath.Abs("unused.conf")
	// Block the first start inside admission while other starts queue.
	entered, release := make(chan struct{}), make(chan struct{})
	s.load = func(string) (core.SessionConfig, error) { close(entered); <-release; return core.SessionConfig{}, nil }
	results := make(chan Response, 17)
	start := Request{Version: Version, Command: "start", Instance: s.instance, Config: path}
	go func() { results <- s.dispatch(context.Background(), start) }()
	<-entered
	var ready sync.WaitGroup
	ready.Add(16)
	for i := 0; i < 16; i++ {
		go func() { ready.Done(); results <- s.dispatch(context.Background(), start) }()
	}
	ready.Wait()
	close(release)
	successes := 0
	for i := 0; i < 17; i++ {
		a := <-results
		if a.Error == "" {
			successes++
		} else if a.Error != "session_already_running" {
			t.Fatal(a)
		}
	}
	if successes != 1 || e.starts != 1 {
		t.Fatalf("starts=%d successes=%d", e.starts, successes)
	}
	// Concurrent exact stops admit only one mutation.
	for i := 0; i < 16; i++ {
		go func() {
			results <- s.dispatch(context.Background(), Request{Version: Version, Command: "stop", Instance: s.instance, Session: "1"})
		}()
	}
	successes = 0
	for i := 0; i < 16; i++ {
		a := <-results
		if a.Error == "" {
			successes++
		} else if a.Error != "stale_session" {
			t.Fatal(a)
		}
	}
	if successes != 1 || e.stops != 1 {
		t.Fatalf("stops=%d successes=%d", e.stops, successes)
	}
}

func daemonWire(t *testing.T, s *Server, line string) []byte {
	t.Helper()
	client, server := net.Pipe()
	done := make(chan struct{})
	go func() { s.handle(context.Background(), server); close(done) }()
	if _, err := io.WriteString(client, line+"\n"); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(client)
	client.Close()
	<-done
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func TestDaemonGuardWireContract(t *testing.T) {
	s, e := guardServer()
	var a Response
	data := daemonWire(t, s, `{"version":1,"command":"hello","id":"handshake"}`)
	if err := json.Unmarshal(data, &a); err != nil {
		t.Fatal(err)
	}
	if !a.DaemonSessionGuards || a.Instance != s.instance || a.ID != "handshake" {
		t.Fatal(a)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	if string(fields["daemon_session_guards"]) != "true" {
		t.Fatal(string(data))
	}
	for _, line := range []string{
		`{"version":1,"command":"stop","instance":"old","instance":""}`,
		`{"version":1,"command":"stop","Instance":"old"}`,
		`{"version":1,"command":"stop","inſtance":null}`,
		`{"version":1,"command":"stop","ſession":null}`,
		`{"version":1,"command":"stop","unknown":true}`,
		`{"version":1,"command":"stop","instance":"old","in\u0073tance":null}`,
		`{"version":1,"command":"stop","instance":null}`,
		`{"version":1,"command":"stop","instance":""}`,
		`{"version":1,"command":"stop","session":""}`,
		`{"version":1,"command":"start","instance":"old","session":null}`,
	} {
		if data := daemonWire(t, s, line); len(data) != 0 {
			t.Fatalf("accepted ambiguous JSON: %s", data)
		}
	}
	if e.stops != 0 || e.starts != 0 {
		t.Fatal("invalid wire request mutated engine")
	}
	path, _ := filepath.Abs("unused.conf")
	request, _ := json.Marshal(Request{Version: Version, Command: "start", Instance: s.instance, Config: path})
	if err := json.Unmarshal(daemonWire(t, s, string(request)), &a); err != nil || a.Error != "" {
		t.Fatalf("%+v %v", a, err)
	}
	request, _ = json.Marshal(Request{Version: Version, Command: "stop", Instance: s.instance, Session: "old"})
	data = daemonWire(t, s, string(request))
	if err := json.Unmarshal(data, &a); err != nil || a.Error != "stale_session" || a.Status.Session.ID != "1" {
		t.Fatalf("%s %v", data, err)
	}
	if e.stops != 0 {
		t.Fatal("stale wire stop mutated engine")
	}
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	var status map[string]json.RawMessage
	if err := json.Unmarshal(fields["status"], &status); err != nil {
		t.Fatal(err)
	}
	if status["Session"] == nil || status["State"] == nil || status["session"] != nil {
		t.Fatal(string(data))
	}
	request, _ = json.Marshal(Request{Version: Version, Command: "stop", Instance: s.instance, Session: "1"})
	a = Response{}
	if err := json.Unmarshal(daemonWire(t, s, string(request)), &a); err != nil || a.Error != "" || a.Status.Session.Active {
		t.Fatalf("%+v %v", a, err)
	}
	if e.stops != 1 {
		t.Fatal("guarded wire stop was not executed")
	}
}

// admissionSnapshotEngine checks the contract without relying on goroutine timing.
type admissionSnapshotEngine struct {
	guardEngine
	command          *sync.Mutex
	outsideAdmission bool
}

func (e *admissionSnapshotEngine) Status() core.Status {
	if e.command.TryLock() {
		e.outsideAdmission = true
		e.command.Unlock()
	}
	return e.guardEngine.Status()
}

func TestDaemonGuardRejectionSnapshotAdmission(t *testing.T) {
	for _, command := range []string{"start", "stop", "shutdown"} {
		t.Run(command, func(t *testing.T) {
			for _, request := range []Request{
				{Instance: "current"}, // Missing stop session or guards on shutdown.
				{Session: "orphan"},
				{ID: strings.Repeat("x", 65)},
				{Installation: "private"},
				{ChallengeID: "unexpected"},
			} {
				e := &admissionSnapshotEngine{}
				s := NewServer(e)
				e.command = &s.command
				s.load = func(string) (core.SessionConfig, error) {
					t.Fatal("rejected request loaded configuration")
					return core.SessionConfig{}, nil
				}
				request.Version, request.Command = Version, command
				a := s.dispatch(context.Background(), request)
				if a.Error == "" || a.Instance != s.instance || e.outsideAdmission || e.starts != 0 || e.stops != 0 {
					t.Fatalf("request=%+v response=%+v outside admission=%v starts=%d stops=%d", request, a, e.outsideAdmission, e.starts, e.stops)
				}
			}
		})
	}
}
