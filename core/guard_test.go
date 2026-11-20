package core

import (
	"context"
	"reflect"
	"testing"
	"time"

	"bimeron/internal/guard"
)

// waitNoSessions fails when an earlier test left a run registered, since the
// guard hands panics to every registered session.
func waitNoSessions(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for guard.Active() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("a session from another test is still running")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A panic in a guarded Core goroutine ends the run through the crash path:
// protection is kept, the run is released, and the guarded goroutine then
// rethrows the original panic itself.
func TestGuardedGoroutinePanicRunsCrashCleanup(t *testing.T) {
	waitNoSessions(t)
	rethrown := make(chan any, 1)
	defer guard.SetRethrow(func(p any) { rethrown <- p })()
	b := &protectedBackend{fakeBackend: fakeBackend{open: func(ctx context.Context) (session, error) {
		guard.Go(func() { panic("relay") })
		<-ctx.Done()
		return nil, ctx.Err()
	}}}
	e := testEngine(b)
	repanicked := make(chan any, 1)
	e.repanic = func(p any) { repanicked <- p }
	if err := e.Start(testDeadline(t), killSwitchConfig()); err != nil {
		t.Fatal(err)
	}
	select {
	case p := <-rethrown:
		if p != "relay" {
			t.Fatal(p)
		}
	case <-testDeadline(t).Done():
		t.Fatal("crash path not taken")
	}
	if _, releases, retains, installed := b.snapshot(); releases != 1 || retains != 1 || !installed {
		t.Fatal("crash cleanup released protection", releases, retains, installed)
	}
	select {
	case p := <-repanicked:
		t.Fatal("run goroutine rethrew a guarded panic", p)
	default:
	}
	waitNoSessions(t)
}

// Stop cancels the context first. A panic claimed during DNS cleanup must
// still retain WFP, even though the context already carries the Stop cause.
func TestNativeStopRacingCrashDuringDNSCleanup(t *testing.T) {
	waitNoSessions(t)
	ctx := testDeadline(t)
	dnsStarted, dispatched := make(chan struct{}), make(chan struct{})
	rethrown := make(chan any, 1)
	defer guard.SetRethrow(func(p any) { rethrown <- p })()
	unregister := guard.Register(func(any) <-chan struct{} { close(dispatched); return dispatched })
	defer unregister()
	var steps []string
	e := testEngine(fakeBackend{openConfig: func(_ context.Context, c SessionConfig) (session, error) {
		return &protectedIKEv2Session{native: fakeSession{}, guard: protectionTestGuard{&steps}, commitStop: c.commitNativeStop, cleanupDNS: func() error {
			close(dnsStarted)
			select {
			case <-dispatched:
			case <-ctx.Done():
			}
			return nil
		}}, nil
	}})
	if err := e.Start(ctx, testConfig()); err != nil {
		t.Fatal(err)
	}
	awaitState(t, e, Connected)
	stopCtx, cancelStop := context.WithCancel(ctx)
	defer cancelStop()
	stopped := make(chan error, 1)
	go func() { stopped <- e.Stop(stopCtx) }()
	select {
	case <-dnsStarted:
	case <-ctx.Done():
		t.Fatal("Stop never reached DNS cleanup")
	}
	guard.Go(func() { panic("during DNS cleanup") })
	select {
	case p := <-rethrown:
		if p != "during DNS cleanup" {
			t.Fatal(p)
		}
	case <-ctx.Done():
		t.Fatal("crash cleanup did not finish")
	}
	if !reflect.DeepEqual(steps, []string{"retain-wfp"}) {
		t.Fatal(steps)
	}
	cancelStop()
	if err := <-stopped; err != context.Canceled {
		t.Fatalf("Stop returned %v after crash", err)
	}
}

// Open closes the protected session when independent DNS setup returns after
// Stop. The context still carries Stop even though a crash has since won.
func TestNativeCloseAfterStopThenCrashDuringSetup(t *testing.T) {
	waitNoSessions(t)
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	var steps []string
	dispatched := make(chan struct{})
	rethrown := make(chan any, 1)
	defer guard.SetRethrow(func(p any) { rethrown <- p })()
	claimed, commit, unregister := guard.RegisterSession(func(any) <-chan struct{} {
		cancel(errGuardedPanic)
		close(dispatched)
		return dispatched
	})
	defer unregister()
	s := &protectedIKEv2Session{setupContext: ctx, retainProtection: claimed, commitStop: commit, native: protectionTestSession{steps: &steps}, guard: protectionTestGuard{&steps}, cleanupDNS: func() error { steps = append(steps, "dns"); return nil }}
	cancel(context.Canceled)
	guard.Go(func() { panic("during setup") })
	select {
	case <-rethrown:
	case <-testDeadline(t).Done():
		t.Fatal("panic was not dispatched")
	}
	if context.Cause(ctx) != context.Canceled {
		t.Fatal(context.Cause(ctx))
	}
	if err := s.Close(); err == nil || !reflect.DeepEqual(steps, []string{"ras", "retain-wfp"}) {
		t.Fatalf("cleanup %v, error %v", steps, err)
	}
}

// Model the interval after Start admits the run and before its goroutine
// registers with the panic guard. The later cancellation has no panic cause.
func TestNativeCleanupAfterMissedOwnerPanicDispatch(t *testing.T) {
	waitNoSessions(t)
	e := &Engine{active: true}
	e.MarkAbandon()
	var rethrown any
	defer guard.SetRethrow(func(p any) { rethrown = p })()
	func() {
		defer guard.Recover()
		panic("owner")
	}()
	claimed, commit, unregister := guard.RegisterSession(func(any) <-chan struct{} {
		t.Fatal("unexpected dispatch")
		return nil
	})
	defer unregister()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if rethrown != "owner" || claimed() || context.Cause(ctx) != context.Canceled {
		t.Fatal("expected missed dispatch and ordinary cancellation")
	}
	var cfg SessionConfig
	e.configureNativeCleanup(&cfg, claimed, commit)
	var steps []string
	status := NativeStatus{DNS: "active", WFP: "active"}
	s := &protectedIKEv2Session{
		setupContext: ctx, retainProtection: cfg.retainNativeProtection, commitStop: cfg.commitNativeStop,
		native: protectionTestSession{steps: &steps}, guard: protectionTestGuard{&steps},
		cleanupDNS: func() error { steps = append(steps, "dns"); return nil },
		update:     func(f func(*NativeStatus)) { f(&status) },
	}
	err := s.Close()
	if err == nil || !reflect.DeepEqual(steps, []string{"ras", "retain-wfp"}) || status.DNS != "retained" || status.WFP != "retained" || !status.RecoveryRequired {
		t.Fatalf("cleanup %v, status %+v, error %v", steps, status, err)
	}
	if cfg.commitNativeStop() {
		t.Fatal("WFP release committed after abandonment")
	}
}
