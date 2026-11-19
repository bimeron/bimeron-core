package control

import (
	"context"
	"errors"
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

	if kept, _ := s.StopForUpdate(record); kept || e.abandoned {
		t.Fatal("stop without a hold kept protection")
	}
	a := s.readinessResponse(Request{Version: Version, Command: "prepare_update"})
	if a.Error != "" || a.Status.KillSwitch != core.KillSwitchActive || a.Status.Session != nil {
		t.Fatal("unexpected prepare_update answer", a)
	}
	now = now.Add(UpdateHoldWindow - time.Second)
	if kept, err := s.StopForUpdate(record); !kept || err != nil || !e.abandoned || len(recorded) != 1 || recorded[0] != strings.Repeat("ab", 32) {
		t.Fatal("hold not applied", kept, err, e.abandoned, recorded)
	}
	e.abandoned = false
	if kept, _ := s.StopForUpdate(record); kept || e.abandoned {
		t.Fatal("hold applied twice")
	}
	s.readinessResponse(Request{Version: Version, Command: "prepare_update"})
	now = now.Add(UpdateHoldWindow)
	if kept, _ := s.StopForUpdate(record); kept || e.abandoned || len(recorded) != 1 {
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
		s.readinessResponse(Request{Version: Version, Command: "prepare_update"})
		var recorded int
		kept, err := s.StopForUpdate(func(string) error { recorded++; return errors.New("disk full") })
		if !kept || (recorded == 1) != tc.record || (err != nil) != tc.record || !e.abandoned {
			t.Fatal(tc.killSwitch, kept, recorded, err, e.abandoned)
		}
	}
}

// prepare_update is a readiness command only and accepts no session fields.
func TestPrepareUpdateRequestShape(t *testing.T) {
	s := NewServer(&holdEngine{events: make(chan core.Event)})
	for _, r := range []Request{{Version: Version, Command: "prepare_update", Config: "x.conf"}, {Version: Version, Command: "prepare_update", Session: "s"}, {Version: 0, Command: "prepare_update"}} {
		if a := s.readinessResponse(r); a.Error != "invalid_request" {
			t.Fatal(r, a)
		}
	}
	if a := s.dispatch(context.Background(), Request{Version: Version, Command: "prepare_update"}); a.Error == "" {
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
	s.readinessAnswer(Request{Version: Version, Command: "prepare_update"}, fakeWatch{alive: false, closed: &closed})
	if kept, _ := s.StopForUpdate(nil); kept || e.abandoned || closed != 1 {
		t.Fatal("hold of a dead updater applied", kept, e.abandoned, closed)
	}
	s.readinessAnswer(Request{Version: Version, Command: "prepare_update"}, fakeWatch{alive: true, closed: &closed})
	s.readinessAnswer(Request{Version: Version, Command: "prepare_update"}, fakeWatch{alive: true, closed: &closed})
	if closed != 2 {
		t.Fatal("replaced hold not released", closed)
	}
	s.dispatch(context.Background(), Request{Version: Version, Command: "stop"})
	if kept, _ := s.StopForUpdate(nil); kept || e.abandoned || closed != 3 {
		t.Fatal("user stop did not cancel the hold", kept, e.abandoned, closed)
	}
	s.readinessAnswer(Request{Version: Version, Command: "prepare_update"}, fakeWatch{alive: true, closed: &closed})
	if kept, _ := s.StopForUpdate(nil); !kept || !e.abandoned || closed != 4 {
		t.Fatal("live updater's hold not applied", kept, e.abandoned, closed)
	}
}
