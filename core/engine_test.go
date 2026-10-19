package core

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeBackend struct {
	acquire    func(context.Context) (func(), error)
	open       func(context.Context) (session, error)
	openConfig func(context.Context, SessionConfig) (session, error)
}

func (b fakeBackend) Acquire(ctx context.Context) (func(), error) {
	if b.acquire != nil {
		return b.acquire(ctx)
	}
	return func() {}, nil
}

func (b fakeBackend) Open(ctx context.Context, c SessionConfig, _ func(string, string)) (session, error) {
	if b.openConfig != nil {
		return b.openConfig(ctx, c)
	}
	return b.open(ctx)
}

type fakeSession struct {
	wait  func(context.Context) error
	close func() error
}

func (s fakeSession) Wait(ctx context.Context) error {
	if s.wait != nil {
		return s.wait(ctx)
	}
	<-ctx.Done()
	return ctx.Err()
}
func (s fakeSession) Close() error {
	if s.close != nil {
		return s.close()
	}
	return nil
}
func testConfig() SessionConfig {
	c := DefaultConfig()
	c.Resolve = func(context.Context) (Profile, error) { return Profile{}, nil }
	return c
}
func testEngine(b backend) *Engine {
	e := New(Options{RetryMin: time.Millisecond, RetryMax: 4 * time.Millisecond})
	e.factory = func(SessionConfig) backend { return b }
	return e
}
func testDeadline(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)
	return ctx
}
func awaitState(t *testing.T, e *Engine, state State) {
	t.Helper()
	ctx := testDeadline(t)
	for {
		select {
		case event := <-e.Events():
			if event.Code == "state" && event.State == state {
				return
			}
		case <-ctx.Done():
			t.Fatalf("never reached %s: %+v", state, e.Status())
		}
	}
}

func TestLifecycleAndConcurrentStop(t *testing.T) {
	var closed, released atomic.Int32
	e := testEngine(fakeBackend{acquire: func(context.Context) (func(), error) { return func() { released.Add(1) }, nil }, open: func(context.Context) (session, error) {
		return fakeSession{close: func() error { closed.Add(1); return nil }}, nil
	}})
	ctx := testDeadline(t)
	for cycle := 1; cycle <= 2; cycle++ {
		if err := e.Start(ctx, testConfig()); err != nil {
			t.Fatal(err)
		}
		awaitState(t, e, Connected)
		if err := e.Start(ctx, testConfig()); err == nil {
			t.Fatal("double start accepted")
		}
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := e.Stop(ctx); err != nil {
					t.Error(err)
				}
			}()
		}
		wg.Wait()
		if closed.Load() != int32(cycle) || released.Load() != int32(cycle) || e.Status().State != Disconnected {
			t.Fatalf("resources/state: %d %d %+v", closed.Load(), released.Load(), e.Status())
		}
	}
}

func TestStopEmitsOneStoppingEvent(t *testing.T) {
	e := testEngine(fakeBackend{open: func(context.Context) (session, error) { return fakeSession{}, nil }})
	ctx := testDeadline(t)
	if err := e.Start(ctx, testConfig()); err != nil {
		t.Fatal(err)
	}
	awaitState(t, e, Connected)
	if err := e.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	stopping := 0
	for {
		select {
		case event := <-e.Events():
			if event.State == Stopping {
				stopping++
			}
		default:
			if stopping != 1 {
				t.Fatalf("stopping events: %d", stopping)
			}
			return
		}
	}
}

func TestReconnectClosesBeforeOpening(t *testing.T) {
	var calls atomic.Int32
	var closed atomic.Bool
	e := testEngine(fakeBackend{open: func(context.Context) (session, error) {
		if calls.Add(1) == 1 {
			return fakeSession{wait: func(context.Context) error { return fault("network_changed", true) }, close: func() error { closed.Store(true); return nil }}, nil
		}
		if !closed.Load() {
			t.Error("opened new tunnel before cleaning old")
		}
		return fakeSession{}, nil
	}})
	ctx := testDeadline(t)
	if err := e.Start(ctx, testConfig()); err != nil {
		t.Fatal(err)
	}
	awaitState(t, e, Reconnecting)
	awaitState(t, e, Connected)
	if e.Status().Attempt != 2 {
		t.Fatal(e.Status())
	}
	if err := e.Stop(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestPermanentSessionFailureDoesNotReconnect(t *testing.T) {
	var opens atomic.Int32
	engine := testEngine(fakeBackend{open: func(context.Context) (session, error) {
		opens.Add(1)
		return fakeSession{wait: func(context.Context) error { return fault("access_key_unavailable", false) }}, nil
	}})
	ctx := testDeadline(t)
	if err := engine.Start(ctx, testConfig()); err != nil {
		t.Fatal(err)
	}
	if err := engine.Wait(ctx); err == nil || err.Error() != "access_key_unavailable" {
		t.Fatal(err)
	}
	if opens.Load() != 1 || engine.Status().State != Failed {
		t.Fatal(engine.Status())
	}
	for len(engine.Events()) > 0 {
		if event := <-engine.Events(); event.State == Reconnecting {
			t.Fatal("reconnect state emitted for permanent failure")
		}
	}
}

func TestCancelDuringStartupWaitsForRollback(t *testing.T) {
	entered := make(chan struct{})
	cleanupStarted := make(chan struct{})
	allowCleanup := make(chan struct{})
	e := testEngine(fakeBackend{open: func(ctx context.Context) (session, error) {
		close(entered)
		<-ctx.Done()
		close(cleanupStarted)
		<-allowCleanup
		return nil, ctx.Err()
	}})
	ctx := testDeadline(t)
	if err := e.Start(ctx, testConfig()); err != nil {
		t.Fatal(err)
	}
	<-entered
	short, cancel := context.WithTimeout(ctx, 10*time.Millisecond)
	defer cancel()
	if err := e.Stop(short); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	<-cleanupStarted
	if err := e.Start(ctx, testConfig()); err == nil {
		t.Fatal("start allowed during rollback")
	}
	close(allowCleanup)
	if err := e.Stop(ctx); err != nil {
		t.Fatal(err)
	}
}
func TestCleanupFailureStopsRetries(t *testing.T) {
	var opens atomic.Int32
	e := testEngine(fakeBackend{open: func(context.Context) (session, error) {
		opens.Add(1)
		return fakeSession{wait: func(context.Context) error { return fault("network_changed", true) }, close: func() error { return fault("cleanup_failed_run_recover", false) }}, nil
	}})
	ctx := testDeadline(t)
	if err := e.Start(ctx, testConfig()); err != nil {
		t.Fatal(err)
	}
	if err := e.Wait(ctx); err == nil || err.Error() != "cleanup_failed_run_recover" {
		t.Fatal(err)
	}
	if opens.Load() != 1 || e.Status().State != Failed {
		t.Fatal("unsafe retry", e.Status())
	}
}
func TestOfflineStartupRetriesAndCanStop(t *testing.T) {
	var opens atomic.Int32
	e := testEngine(fakeBackend{open: func(context.Context) (session, error) { opens.Add(1); return nil, fault("network_unavailable", true) }})
	ctx := testDeadline(t)
	if err := e.Start(ctx, testConfig()); err != nil {
		t.Fatal(err)
	}
	awaitState(t, e, Reconnecting)
	if err := e.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if opens.Load() < 1 || e.Status().State != Disconnected {
		t.Fatal(e.Status())
	}
}
func TestFatalStartupAndCancelledRollback(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		t.Run(map[bool]string{true: "cancelled", false: "fatal"}[cancelled], func(t *testing.T) {
			ctx, cancel := context.WithCancel(testDeadline(t))
			defer cancel()
			e := testEngine(fakeBackend{open: func(context.Context) (session, error) {
				if cancelled {
					cancel()
				}
				return nil, fault("cleanup_failed_run_recover", false)
			}})
			if err := e.Start(ctx, testConfig()); err != nil {
				t.Fatal(err)
			}
			if err := e.Wait(testDeadline(t)); err == nil {
				t.Fatal("failure swallowed")
			}
			if e.Status().State != Failed {
				t.Fatal(e.Status())
			}
		})
	}
}
func TestSlowEventsDoNotBlockStop(t *testing.T) {
	e := testEngine(fakeBackend{open: func(context.Context) (session, error) { return fakeSession{}, nil }})
	ctx := testDeadline(t)
	if err := e.Start(ctx, testConfig()); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 500; i++ {
		e.transition(Connecting, nil)
	}
	if err := e.Stop(ctx); err != nil {
		t.Fatal(err)
	}
}
func TestCleanupOrderAndAllActionsAfterFailure(t *testing.T) {
	var order []int
	c := &cleanup{}
	for i := 0; i < 4; i++ {
		c.add(func() error {
			order = append(order, i)
			if i == 2 {
				return errors.New("failure")
			}
			return nil
		})
	}
	if c.Close() == nil {
		t.Fatal("lost cleanup error")
	}
	_ = c.Close()
	if !reflect.DeepEqual(order, []int{3, 2, 1, 0}) {
		t.Fatal(order)
	}
}
func TestResumeDetection(t *testing.T) {
	now := time.Now()
	if resumed(now, now.Add(5*time.Second)) || !resumed(now, now.Add(time.Minute)) {
		t.Fatal("bad resume detection")
	}
}
