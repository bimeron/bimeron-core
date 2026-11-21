package control

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"bimeron/core"
	"bimeron/internal/telemetry"
)

// holdEngine reports a run that owns kill switch protection and records
// whether the server marked it abandoned.
type holdEngine struct {
	mu         sync.Mutex
	status     core.Status
	abandoned  bool
	events     chan core.Event
	statusRead int
	beforeMark func()
}

func (e *holdEngine) Start(context.Context, core.SessionConfig) error { return nil }
func (e *holdEngine) Stop(context.Context) error                      { return nil }
func (e *holdEngine) Status() core.Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.statusRead++
	return e.status
}
func (e *holdEngine) Events() <-chan core.Event { return e.events }
func (e *holdEngine) Stats() telemetry.Snapshot { return telemetry.Snapshot{} }
func (e *holdEngine) MarkAbandon() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.abandoned = true
}

func (e *holdEngine) MarkPreparedUpdate(record func(string) error, valid func() bool, renew func() error) error {
	if e.beforeMark != nil {
		e.beforeMark()
	}
	if !valid() {
		return errors.New("expired")
	}
	e.MarkAbandon()
	if record != nil && (e.status.KillSwitch == core.KillSwitchActive || e.status.KillSwitch == core.KillSwitchHolding) {
		return record(e.status.Session.ProfileID)
	}
	return nil
}

func TestUpdateStopSerializesRecordWithIPC(t *testing.T) {
	e := &holdEngine{status: heldStatus(core.KillSwitchActive)}
	s := NewServer(e)
	s.readinessResponse(Request{Version: Version, Command: "prepare_update", ID: strings.Repeat("A", 26)})
	entered, resume := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := s.consumePrepared(func(string) error { close(entered); <-resume; return nil })
		done <- err
	}()
	<-entered
	unlocked := s.command.TryLock()
	if unlocked {
		s.command.Unlock()
	}
	close(resume)
	if err := <-done; unlocked || err != nil {
		t.Fatal("IPC command lock during marker write", unlocked, err)
	}
}

func TestDelayedPreparedStopAndLateProtectedStart(t *testing.T) {
	for _, expired := range []bool{false, true} {
		e := &holdEngine{status: core.Status{State: core.Disconnected}}
		s := NewServer(e)
		now := time.Unix(100, 0)
		s.clock = func() time.Time { return now }
		prepared := s.readinessResponse(Request{Version: Version, Command: "prepare_update", ID: strings.Repeat("B", 26)})
		if prepared.Error != "" || prepared.Status.KillSwitch != "" {
			t.Fatal(prepared)
		}
		e.status = heldStatus(core.KillSwitchActive)
		if expired {
			e.beforeMark = func() { now = now.Add(UpdateHoldWindow) }
		}
		var recorded string
		id, err := s.stopPreparedUpdateForTest(func(profile, transaction string) error {
			if transaction != prepared.ID {
				t.Fatal(transaction)
			}
			recorded = profile
			return nil
		})
		if expired {
			if err == nil || id != "" || e.abandoned || recorded != "" {
				t.Fatal("expired stop admitted")
			}
		} else if err != nil || id != prepared.ID || recorded != e.status.Session.ProfileID {
			t.Fatal("late protected run missing", id, err, recorded)
		}
	}
}

func TestRejectedPrepareReleasesWatch(t *testing.T) {
	s := NewServer(&holdEngine{})
	closed := 0
	a := s.readinessAnswer(Request{Version: Version, Command: "prepare_update", ID: strings.Repeat("A", 26), Config: "extra"}, fakeWatch{alive: true, closed: &closed})
	if a.Error != "invalid_request" || closed != 1 {
		t.Fatal(a, closed)
	}
	if kept, _ := s.consumePrepared(nil); kept {
		t.Fatal("invalid request armed hold")
	}
}

func TestPrepareRecognizesOnlyVerifiedResidual(t *testing.T) {
	e := &holdEngine{status: core.Status{State: core.Failed, KillSwitch: core.KillSwitchResidual, ResidualReason: core.ResidualUpdate, LastError: "cleanup_failed_run_recover"}}
	s := NewServer(e)
	for _, id := range []string{"", "invalid", strings.Repeat("ab", 32)} {
		e.status.ResidualProfile = id
		a := s.readinessResponse(Request{Version: Version, Command: "prepare_update", ID: strings.Repeat("A", 26)})
		if (a.Status.ResidualReason == core.ResidualUpdate) != (len(id) == 64) || a.Status.ResidualProfile != "" {
			t.Fatal(a)
		}
	}
}

func heldStatus(killSwitch string) core.Status {
	return core.Status{State: core.Connected, KillSwitch: killSwitch, Session: &core.SessionInfo{ProfileID: strings.Repeat("ab", 32)}}
}

// prepare_update arms a one-shot hold for the next stop within the window:
// the stop records the held profile and keeps protection by abandoning the
// session. Without a hold, after it expired, or once consumed, a stop is an
// ordinary stop.
func TestUpdateHoldAppliesToOneStopWithinWindow(t *testing.T) {
	e := &holdEngine{status: heldStatus(core.KillSwitchActive), events: make(chan core.Event)}
	s := NewServer(e)
	now := time.Unix(1_800_000_000, 0)
	s.clock = func() time.Time { return now }
	var recorded []string
	record := func(id string) error { recorded = append(recorded, id); return nil }

	if kept, _ := s.consumePrepared(record); kept || e.abandoned {
		t.Fatal("stop without a hold kept protection")
	}
	a := s.readinessResponse(Request{Version: Version, Command: "prepare_update", ID: strings.Repeat("A", 26)})
	if a.Error != "" || a.Status.KillSwitch != core.KillSwitchActive || a.Status.Session != nil {
		t.Fatal("unexpected prepare_update answer", a)
	}
	now = now.Add(UpdateHoldWindow - time.Second)
	if kept, err := s.consumePrepared(record); !kept || err != nil || !e.abandoned || len(recorded) != 1 || recorded[0] != strings.Repeat("ab", 32) {
		t.Fatal("hold not applied", kept, err, e.abandoned, recorded)
	}
	e.abandoned = false
	if kept, _ := s.consumePrepared(record); kept || e.abandoned {
		t.Fatal("hold applied twice")
	}
	s.readinessResponse(Request{Version: Version, Command: "prepare_update", ID: strings.Repeat("A", 26)})
	now = now.Add(UpdateHoldWindow)
	if kept, _ := s.consumePrepared(record); kept || e.abandoned || len(recorded) != 1 {
		t.Fatal("expired hold applied")
	}
}

// A hold keeps only protection a run owns: without it (a user's stop already
// ended the run, or no kill switch) nothing is recorded. A failed record
// still keeps the protection, reported as plain residual.
func TestUpdateHoldRecordsOnlyOwnedProtection(t *testing.T) {
	for _, tc := range []struct {
		killSwitch string
		record     bool
	}{{core.KillSwitchHolding, true}, {"", false}, {core.KillSwitchResidual, false}} {
		e := &holdEngine{status: heldStatus(tc.killSwitch), events: make(chan core.Event)}
		s := NewServer(e)
		s.readinessResponse(Request{Version: Version, Command: "prepare_update", ID: strings.Repeat("A", 26)})
		var recorded int
		kept, err := s.consumePrepared(func(string) error { recorded++; return errors.New("disk full") })
		if kept == tc.record || (recorded == 1) != tc.record || (err != nil) != tc.record || !e.abandoned {
			t.Fatal(tc.killSwitch, kept, recorded, err, e.abandoned)
		}
	}
}

// prepare_update is a readiness command only and accepts no session fields.
func TestPrepareUpdateRequestShape(t *testing.T) {
	s := NewServer(&holdEngine{events: make(chan core.Event)})
	for _, r := range []Request{{Version: Version, Command: "prepare_update", ID: strings.Repeat("A", 26), Config: "x.conf"}, {Version: Version, Command: "prepare_update", ID: strings.Repeat("A", 26), Session: "s"}, {Version: 0, Command: "prepare_update", ID: strings.Repeat("A", 26)}} {
		if a := s.readinessResponse(r); a.Error != "invalid_request" {
			t.Fatal(r, a)
		}
	}
	if a := s.dispatch(context.Background(), Request{Version: Version, Command: "prepare_update", ID: strings.Repeat("A", 26)}); a.Error == "" {
		t.Fatal("prepare_update reachable on the control pipe", a)
	}
}

type fakeWatch struct {
	alive  bool
	closed *int
}

func (w fakeWatch) Alive() bool { return w.alive }
func (w fakeWatch) Close()      { *w.closed++ }

// A hold is bound to the updater that asked for it: once that process is
// gone the stop is ordinary. A user's stop cancels a pending hold. Watches
// are always closed.
func TestUpdateHoldBoundToUpdaterAndCancelledByStop(t *testing.T) {
	e := &holdEngine{status: heldStatus(core.KillSwitchActive), events: make(chan core.Event)}
	s := NewServer(e)
	closed := 0
	s.readinessAnswer(Request{Version: Version, Command: "prepare_update", ID: strings.Repeat("A", 26)}, fakeWatch{alive: false, closed: &closed})
	if kept, _ := s.consumePrepared(nil); kept || e.abandoned || closed != 1 {
		t.Fatal("hold of a dead updater applied", kept, e.abandoned, closed)
	}
	s.readinessAnswer(Request{Version: Version, Command: "prepare_update", ID: strings.Repeat("A", 26)}, fakeWatch{alive: true, closed: &closed})
	s.readinessAnswer(Request{Version: Version, Command: "prepare_update", ID: strings.Repeat("A", 26)}, fakeWatch{alive: true, closed: &closed})
	if closed != 2 {
		t.Fatal("replaced hold not released", closed)
	}
	s.dispatch(context.Background(), Request{Version: Version, Command: "stop"})
	if kept, _ := s.consumePrepared(nil); kept || e.abandoned || closed != 3 {
		t.Fatal("user stop did not cancel the hold", kept, e.abandoned, closed)
	}
	s.readinessAnswer(Request{Version: Version, Command: "prepare_update", ID: strings.Repeat("A", 26)}, fakeWatch{alive: true, closed: &closed})
	if kept, _ := s.consumePrepared(nil); !kept || !e.abandoned || closed != 4 {
		t.Fatal("live updater's hold not applied", kept, e.abandoned, closed)
	}
}

func (s *Server) consumePrepared(record func(string) error) (bool, error) {
	id, err := s.stopPreparedUpdateForTest(func(profile, transaction string) error {
		if record == nil {
			return nil
		}
		return record(profile)
	})
	return id != "", err
}

func (s *Server) readinessResponse(r Request) Response {
	return s.readinessAnswer(r, fakeWatch{alive: true, closed: new(int)})
}
func (s *Server) readinessAnswer(r Request, peer ProcessWatch) Response {
	var a Response
	s.replyReadiness(context.Background(), time.Now().Add(time.Minute), r, peer, func(v any) error { a = v.(Response); return nil })
	return a
}

func TestPrepareConnectionFailedWrite(t *testing.T) {
	s := NewServer(&holdEngine{})
	client, server := net.Pipe()
	done := make(chan struct{})
	closed := 0
	s.PeerProcess = func(net.Conn) ProcessWatch { return fakeWatch{alive: true, closed: &closed} }
	go func() { defer close(done); s.readinessConnection(context.Background(), server) }()
	if err := json.NewEncoder(client).Encode(Request{Version: Version, Command: "prepare_update", ID: strings.Repeat("A", 26)}); err != nil {
		t.Fatal(err)
	}
	client.Close()
	<-done
	if kept, _ := s.consumePrepared(nil); kept || closed != 1 {
		t.Fatal(kept, closed)
	}
}

func TestPrepareConnectionDelayedCommand(t *testing.T) {
	e := &holdEngine{}
	s := NewServer(e)
	client, server := net.Pipe()
	defer client.Close()
	done, admitted := make(chan struct{}), make(chan struct{})
	closed := 0
	s.PeerProcess = func(net.Conn) ProcessWatch { close(admitted); return fakeWatch{alive: true, closed: &closed} }
	s.command.Lock()
	go func() { defer close(done); s.readinessConnection(context.Background(), server) }()
	err := json.NewEncoder(client).Encode(Request{Version: Version, Command: "prepare_update", ID: strings.Repeat("A", 26)})
	if err == nil {
		<-admitted
		time.Sleep(2 * time.Second)
	}
	s.command.Unlock()
	<-done
	if err != nil {
		t.Fatal(err)
	}
	if kept, _ := s.consumePrepared(nil); kept || closed != 1 || e.statusRead != 0 {
		t.Fatal(kept, closed, e.statusRead)
	}
}

func (s *Server) stopPreparedUpdateForTest(write func(string, string) error) (string, error) {
	s.command.Lock()
	defer s.command.Unlock()
	return s.stopPreparedUpdateLocked(write)
}

type updateTestProcess struct {
	fakeWatch
	pid uint32
}

func (p updateTestProcess) ProcessID() uint32 { return p.pid }

func TestCommitUpdateRequiresPreparedTransactionAndProcess(t *testing.T) {
	s := NewServer(&holdEngine{})
	stops := 0
	s.UpdateCommitted = func(string) { stops++ }
	id := strings.Repeat("A", 26)
	closed := 0
	process := func(pid uint32) updateTestProcess {
		return updateTestProcess{fakeWatch{alive: true, closed: &closed}, pid}
	}
	send := func(command, id string, pid uint32) Response {
		return s.readinessAnswer(Request{Version: Version, Command: command, ID: id}, process(pid))
	}
	if a := send("prepare_update", id, 10); a.Error != "" {
		t.Fatal(a)
	}
	if a := send("commit_update", id, 11); a.Error == "" {
		t.Fatal("foreign process committed")
	}
	if a := send("commit_update", strings.Repeat("B", 26), 10); a.Error == "" {
		t.Fatal("foreign transaction committed")
	}
	if a := send("commit_update", id, 10); a.Error != "" || a.UpdateTransaction != id {
		t.Fatal(a)
	}
	if a := send("commit_update", id, 10); a.Error == "" || stops != 1 {
		t.Fatal(a, stops)
	}
}
