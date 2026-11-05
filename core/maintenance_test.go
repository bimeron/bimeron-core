package core

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

type maintenanceFakeStore struct {
	gate              maintenanceRequest
	readErr, writeErr error
	writes            atomic.Int32
	write             func(maintenanceResult)
}

func (s *maintenanceFakeStore) ReadGate() (maintenanceRequest, error) { return s.gate, s.readErr }
func (s *maintenanceFakeStore) WriteResult(r maintenanceResult) error {
	s.writes.Add(1)
	if s.write != nil {
		s.write(r)
	}
	return s.writeErr
}
func maintenanceFixture(t *testing.T, e *Engine) (*maintenanceCoordinator, *maintenanceFakeStore, maintenanceRequest) {
	t.Helper()
	r := maintenanceRequest{Identity: maintenanceIdentity{"installation", "boot", "instance"}, Operation: "operation", Request: "request", GateDigest: "digest", Generation: 1, Sequence: 1}
	status := e.Status()
	if status.Session != nil && status.Session.Active {
		r.Session = status.Session.ID
	}
	store := &maintenanceFakeStore{gate: r}
	c, err := newMaintenanceCoordinator(e, store, r.Identity)
	if err != nil {
		t.Fatal(err)
	}
	return c, store, r
}
func TestMaintenanceSealedDirectStart(t *testing.T) {
	e := testEngine(fakeBackend{open: func(context.Context) (session, error) { t.Error("unexpected Open"); return fakeSession{}, nil }})
	c, _, _ := maintenanceFixture(t, e)
	if !c.Status().Sealed {
		t.Fatal("coordinator did not start sealed")
	}
	if err := e.Start(testDeadline(t), testConfig()); !errors.Is(err, errMaintenanceSealed) {
		t.Fatal(err)
	}
}
func TestMaintenanceWaiterReplayAndRetainedFailure(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	unblock := maintenanceUnblock(t, release)
	var closes atomic.Int32
	e := testEngine(fakeBackend{open: func(context.Context) (session, error) {
		return fakeSession{close: func() error {
			closes.Add(1)
			close(entered)
			<-release
			return errors.New("cleanup failed")
		}}, nil
	}})
	ctx := testDeadline(t)
	if err := e.Start(ctx, testConfig()); err != nil {
		t.Fatal(err)
	}
	awaitState(t, e, Connected)
	c, store, r := maintenanceFixture(t, e)
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := c.Shutdown(cancelled, r); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("cleanup not entered")
	}
	if result, err := c.Query(r); err != nil || result.Outcome != maintenancePending {
		t.Fatal(result, err)
	}
	if !c.Status().Sealed {
		t.Fatal("waiter cancellation opened admission")
	}
	conflict := r
	conflict.GateDigest = "other"
	if _, err := c.Shutdown(ctx, conflict); !errors.Is(err, errMaintenanceConflict) {
		t.Fatal(err)
	}
	unblock()
	result, err := c.Shutdown(ctx, r)
	if err != nil || result.Outcome != maintenanceFailed || !result.CleanupFailed || !result.StopCompleted || !result.Inactive {
		t.Fatal(result, err)
	}
	again, err := c.Shutdown(ctx, r)
	if err != nil || again != result || closes.Load() != 1 || store.writes.Load() != 1 {
		t.Fatal(again, err, closes.Load(), store.writes.Load())
	}
	next := r
	next.Operation = "next"
	next.Request = "next"
	if _, err := c.Query(next); !errors.Is(err, errMaintenanceUnknown) {
		t.Fatal(err)
	}
	if _, err := c.Shutdown(ctx, next); !errors.Is(err, errMaintenanceFull) {
		t.Fatal(err)
	}
	if err := e.Start(ctx, testConfig()); !errors.Is(err, errMaintenanceSealed) {
		t.Fatal(err)
	}
}
func TestMaintenanceStoreFaultsAndMismatch(t *testing.T) {
	for _, kind := range []string{"read", "gate", "target", "write"} {
		t.Run(kind, func(t *testing.T) {
			e := New(Options{})
			c, store, r := maintenanceFixture(t, e)
			want := errMaintenanceStorage
			switch kind {
			case "read":
				store.readErr = errors.New("read")
			case "gate":
				store.gate.Sequence++
				want = errMaintenanceConflict
			case "target":
				r.Session = "unexpected"
				store.gate = r
				want = errMaintenanceTarget
			case "write":
				store.writeErr = errors.New("write")
				want = nil
			}
			result, err := c.Shutdown(testDeadline(t), r)
			if !errors.Is(err, want) {
				t.Fatal(result, err)
			}
			if kind == "write" && (result.Outcome != maintenanceStorageFailed || store.writes.Load() != 1) {
				t.Fatal(result)
			}
			if !c.Status().Sealed {
				t.Fatal("fault opened admission")
			}
		})
	}
}
func TestMaintenanceQueriesDuringPublication(t *testing.T) {
	e := New(Options{})
	c, store, r := maintenanceFixture(t, e)
	entered, release := make(chan struct{}), make(chan struct{})
	unblock := maintenanceUnblock(t, release)
	store.write = func(result maintenanceResult) {
		if result.Outcome != maintenanceRecovery {
			t.Error("Stop was treated as cleanup proof", result)
		}
		close(entered)
		<-release
	}
	ctx := testDeadline(t)
	waiter, cancel := context.WithCancel(ctx)
	cancel()
	_, _ = c.Shutdown(waiter, r)
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("publication not entered")
	}
	// These calls must not need command admission, the store or Engine's mutex.
	if c.Status().Result.Outcome != maintenancePending {
		t.Fatal(c.Status())
	}
	if _, err := c.Query(r); err != nil {
		t.Fatal(err)
	}
	_ = e.Status()
	unblock()
	result, err := c.Shutdown(ctx, r)
	if err != nil || result.Outcome != maintenanceRecovery {
		t.Fatal(result, err)
	}
}
func TestMaintenanceFencesScheduledAcquireAndOpen(t *testing.T) {
	for _, phase := range []string{"factory", "acquire"} {
		t.Run(phase, func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			unblock := maintenanceUnblock(t, release)
			var acquires, opens, releases atomic.Int32
			b := fakeBackend{acquire: func(context.Context) (func(), error) {
				acquires.Add(1)
				if phase == "acquire" {
					close(entered)
					<-release
				}
				return func() { releases.Add(1) }, nil
			}, open: func(context.Context) (session, error) { opens.Add(1); return fakeSession{}, nil }}
			e := New(Options{})
			e.factory = func(SessionConfig) backend {
				if phase == "factory" {
					close(entered)
					<-release
				}
				return b
			}
			ctx := testDeadline(t)
			if err := e.Start(ctx, testConfig()); err != nil {
				t.Fatal(err)
			}
			select {
			case <-entered:
			case <-ctx.Done():
				t.Fatal("entry not reached")
			}
			c, _, r := maintenanceFixture(t, e)
			unblock()
			if err := e.Wait(ctx); !errors.Is(err, errMaintenanceSealed) {
				t.Fatal(err)
			}
			if opens.Load() != 0 {
				t.Fatal("Open crossed attached fence")
			}
			if phase == "factory" && acquires.Load() != 0 {
				t.Fatal("Acquire crossed attached fence")
			}
			if phase == "acquire" && releases.Load() != 1 {
				t.Fatal("admitted Acquire was not released")
			}
			// An already terminal Engine failure remains visible to maintenance Stop.
			r.Session = ""
			c.store.(*maintenanceFakeStore).gate = r
			result, err := c.Shutdown(ctx, r)
			if err != nil || !result.CleanupFailed {
				t.Fatal(result, err)
			}
		})
	}
}

// Every owned blocker is released even if an assertion aborts the test.
func maintenanceUnblock(t *testing.T, ch chan struct{}) func() {
	t.Helper()
	var once sync.Once
	unblock := func() { once.Do(func() { close(ch) }) }
	t.Cleanup(unblock)
	return unblock
}

type maintenanceReconnectSession struct {
	entered    chan struct{}
	release    chan struct{}
	reconnects atomic.Int32
	closes     atomic.Int32
}

func (s *maintenanceReconnectSession) Wait(context.Context) error {
	return fault("transport_unavailable", true)
}
func (s *maintenanceReconnectSession) Suspend() { close(s.entered); <-s.release }
func (s *maintenanceReconnectSession) Reconnect(context.Context) error {
	s.reconnects.Add(1)
	return nil
}
func (s *maintenanceReconnectSession) Close() error { s.closes.Add(1); return nil }
func TestMaintenanceFencesPersistentReconnect(t *testing.T) {
	s := &maintenanceReconnectSession{entered: make(chan struct{}), release: make(chan struct{})}
	unblock := maintenanceUnblock(t, s.release)
	e := testEngine(fakeBackend{open: func(context.Context) (session, error) { return s, nil }})
	ctx := testDeadline(t)
	if err := e.Start(ctx, testConfig()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-s.entered:
	case <-ctx.Done():
		t.Fatal("Suspend not entered")
	}
	maintenanceFixture(t, e)
	unblock()
	if err := e.Wait(ctx); !errors.Is(err, errMaintenanceSealed) {
		t.Fatal(err)
	}
	if s.reconnects.Load() != 0 || s.closes.Load() != 1 {
		t.Fatal("persistent resource fence or cleanup failed", s.reconnects.Load(), s.closes.Load())
	}
}
