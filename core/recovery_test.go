package core

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCycleDelay(t *testing.T) {
	want := []time.Duration{1, 2, 4, 8, 15, 15, 15, 15, 15, 15}
	for i, w := range want {
		if got := cycleDelay(time.Second, 15*time.Second, i+1); got != w*time.Second {
			t.Errorf("attempt %d: %v, want %v", i+1, got, w*time.Second)
		}
	}
	if got := cycleDelay(time.Second, 500*time.Millisecond, 1); got != 500*time.Millisecond {
		t.Fatal(got)
	}
}

func TestRequiresRecovery(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{fault("cleanup_failed_run_recover", false), true},
		{fault("kill_switch_arm_failed_run_recover", false), true},
		{errMaintenanceSealed, true},
		{fault("access_key_unavailable", false), false},
		{fault("tunnel_adapter_lost", false), false},
		{fault("transport_check_failed", true), false},
		{errors.New("other"), false},
	} {
		if got := requiresRecovery(tc.err); got != tc.want {
			t.Errorf("%v: %v", tc.err, got)
		}
	}
}

// eventsUntil collects events until match returns true.
func eventsUntil(t *testing.T, e *Engine, match func(Event) bool) []Event {
	t.Helper()
	ctx := testDeadline(t)
	var seen []Event
	for {
		select {
		case ev := <-e.Events():
			seen = append(seen, ev)
			if match(ev) {
				return seen
			}
		case <-ctx.Done():
			t.Fatalf("event not observed; status %+v", e.Status())
		}
	}
}

// Loss of an established session recovers in cycles of ten attempts separated
// by a pause, until a connection succeeds.
func TestEstablishedLossRecoversInCycles(t *testing.T) {
	var opens atomic.Int32
	const failures = 2*cycleAttemptLimit + 3
	e := testEngine(fakeBackend{open: func(context.Context) (session, error) {
		n := opens.Add(1)
		if n == 1 {
			return fakeSession{wait: func(context.Context) error { return fault("network_changed", true) }}, nil
		}
		if n <= 1+failures {
			return nil, fault("transport_check_failed", true)
		}
		return fakeSession{}, nil
	}})
	e.opts.CycleRetryMax = 2 * time.Millisecond
	e.opts.CyclePause = 5 * time.Millisecond
	ctx := testDeadline(t)
	if err := e.Start(ctx, testConfig()); err != nil {
		t.Fatal(err)
	}
	awaitState(t, e, Connected)
	events := eventsUntil(t, e, func(ev Event) bool { return ev.Code == "state" && ev.State == Connected })
	var attempts []int
	var cycles []int
	waits := 0
	for _, ev := range events {
		switch ev.Code {
		case "reconnect_attempt":
			if ev.ReconnectLimit != cycleAttemptLimit || ev.ReconnectPhase != PhaseAttempting {
				t.Fatal(ev)
			}
			attempts = append(attempts, ev.ReconnectAttempt)
			cycles = append(cycles, ev.ReconnectCycle)
		case "reconnect_wait":
			waits++
			if ev.ReconnectAttempt != 0 || ev.ReconnectLimit != 0 || ev.ReconnectPhase != PhaseWaiting || ev.NextAttemptAt.IsZero() || ev.State != Reconnecting {
				t.Fatal(ev)
			}
		}
	}
	// failures+1 attempts: 10 + 10 + 4, the last one succeeds.
	if waits != 2 || len(attempts) != failures+1 {
		t.Fatal(waits, attempts)
	}
	for i, a := range attempts {
		if a != i%cycleAttemptLimit+1 || cycles[i] != i/cycleAttemptLimit+1 {
			t.Fatal(i, attempts, cycles)
		}
	}
	if s := e.Status(); s.ReconnectAttempt != 0 || s.ReconnectLimit != 0 || s.ReconnectCycle != 0 || s.ReconnectPhase != "" || !s.NextAttemptAt.IsZero() || s.LastError != "" {
		t.Fatal("successful recovery did not reset progress", s)
	}
	if err := e.Stop(ctx); err != nil {
		t.Fatal(err)
	}
}

// waitingEngine reaches the inter-cycle wait of an established session.
func waitingEngine(t *testing.T, opens *atomic.Int32, succeedAfter int32) *Engine {
	t.Helper()
	e := testEngine(fakeBackend{open: func(context.Context) (session, error) {
		n := opens.Add(1)
		if n == 1 {
			return fakeSession{wait: func(context.Context) error { return fault("network_changed", true) }}, nil
		}
		if succeedAfter > 0 && n > succeedAfter {
			return fakeSession{}, nil
		}
		return nil, fault("transport_check_failed", true)
	}})
	e.opts.CycleRetryMax = time.Millisecond
	e.opts.CyclePause = time.Hour
	return e
}

// awaitStatus polls Status, which unlike the event stream holds no history.
func awaitStatus(t *testing.T, e *Engine, match func(Status) bool) Status {
	t.Helper()
	ctx := testDeadline(t)
	for {
		if s := e.Status(); match(s) {
			return s
		}
		select {
		case <-ctx.Done():
			t.Fatal("status not reached", e.Status())
		case <-time.After(time.Millisecond):
		}
	}
}

func awaitWaiting(t *testing.T, e *Engine) Status {
	t.Helper()
	ctx := testDeadline(t)
	for {
		if s := e.Status(); s.ReconnectPhase == PhaseWaiting {
			return s
		}
		select {
		case <-ctx.Done():
			t.Fatal("waiting phase not reached", e.Status())
		case <-time.After(time.Millisecond):
		}
	}
}

// The waiting phase omits the attempt counter, so a GUI that shows it only for
// 1 <= ReconnectAttempt <= ReconnectLimit shows plain "Reconnecting".
func TestWaitingPhaseStatusAndReconnectNow(t *testing.T) {
	var opens atomic.Int32
	e := waitingEngine(t, &opens, 1+cycleAttemptLimit)
	ctx := testDeadline(t)
	if err := e.ReconnectNow(); !errors.Is(err, ErrReconnectNotPending) {
		t.Fatal("reconnect without session", err)
	}
	if err := e.Start(ctx, testConfig()); err != nil {
		t.Fatal(err)
	}
	s := awaitWaiting(t, e)
	if s.State != Reconnecting || s.ReconnectCycle != 1 || s.LastError != "transport_check_failed" {
		t.Fatal(s)
	}
	if until := time.Until(s.NextAttemptAt); until < 58*time.Minute || until > time.Hour {
		t.Fatal("next attempt", s.NextAttemptAt)
	}
	data, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(data, &wire); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"ReconnectAttempt", "ReconnectLimit"} {
		if _, present := wire[field]; present {
			t.Fatal(field, string(data))
		}
	}
	if wire["ReconnectPhase"] != PhaseWaiting || wire["ReconnectCycle"] != float64(1) {
		t.Fatal(string(data))
	}
	if _, err := time.Parse(time.RFC3339, wire["NextAttemptAt"].(string)); err != nil {
		t.Fatal(string(data))
	}
	if err := e.ReconnectNow(); err != nil {
		t.Fatal(err)
	}
	awaitStatus(t, e, func(s Status) bool { return s.State == Connected })
	if opens.Load() != 2+cycleAttemptLimit {
		t.Fatal(opens.Load())
	}
	if err := e.ReconnectNow(); !errors.Is(err, ErrReconnectNotPending) {
		t.Fatal("reconnect while connected", err)
	}
	if err := e.Stop(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestNetworkChangeEndsRecoveryWait(t *testing.T) {
	var opens atomic.Int32
	e := waitingEngine(t, &opens, 1+cycleAttemptLimit)
	var network atomic.Value
	network.Store("wifi-a")
	e.observe = func(string) string { return network.Load().(string) }
	e.pollEvery = time.Millisecond
	ctx := testDeadline(t)
	if err := e.Start(ctx, testConfig()); err != nil {
		t.Fatal(err)
	}
	awaitWaiting(t, e)
	network.Store("wifi-b")
	awaitStatus(t, e, func(s Status) bool { return s.State == Connected })
	if opens.Load() != 2+cycleAttemptLimit {
		t.Fatal(opens.Load())
	}
	if err := e.Stop(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestStopDuringRecoveryWait(t *testing.T) {
	var opens atomic.Int32
	e := waitingEngine(t, &opens, 0)
	ctx := testDeadline(t)
	if err := e.Start(ctx, testConfig()); err != nil {
		t.Fatal(err)
	}
	awaitWaiting(t, e)
	if err := e.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if s := e.Status(); s.State != Disconnected || s.ReconnectPhase != "" || !s.NextAttemptAt.IsZero() || s.ReconnectCycle != 0 {
		t.Fatal(s)
	}
}

// A connection that drops again within a minute continues the previous cycle
// position instead of restarting it.
func TestFlappingContinuesCycle(t *testing.T) {
	var opens atomic.Int32
	e := testEngine(fakeBackend{open: func(context.Context) (session, error) {
		n := opens.Add(1)
		if n%3 == 1 {
			return fakeSession{wait: func(context.Context) error { return fault("network_changed", true) }}, nil
		}
		return nil, fault("transport_check_failed", true)
	}})
	e.opts.CycleRetryMax = time.Millisecond
	e.opts.CyclePause = time.Hour
	ctx := testDeadline(t)
	if err := e.Start(ctx, testConfig()); err != nil {
		t.Fatal(err)
	}
	s := awaitWaiting(t, e)
	if s.ReconnectCycle != 1 {
		t.Fatal(s)
	}
	// Each connection consumed one more attempt of the same cycle: ten
	// attempts were reached after fewer than ten failures plus reconnections.
	if opens.Load() > 1+cycleAttemptLimit {
		t.Fatal("flapping restarted the cycle", opens.Load())
	}
	if err := e.Stop(ctx); err != nil {
		t.Fatal(err)
	}
}

// protectedBackend models run-scoped kill switch protection.
type protectedBackend struct {
	fakeBackend
	mu                          sync.Mutex
	acquires, releases, retains int
	installed                   bool
	releaseErr                  error
	lastErr                     error
	retain                      bool
}

func (b *protectedBackend) Acquire(ctx context.Context) (func(), error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.acquires++
	b.installed, b.retain, b.lastErr = true, false, nil
	return func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		b.releases++
		if b.retain {
			b.retains++
			return
		}
		if b.releaseErr != nil {
			b.lastErr = b.releaseErr
			return
		}
		b.installed = false
	}, nil
}
func (b *protectedBackend) Protected() bool     { return true }
func (b *protectedBackend) RetainProtection()   { b.mu.Lock(); b.retain = true; b.mu.Unlock() }
func (b *protectedBackend) ReleaseError() error { b.mu.Lock(); defer b.mu.Unlock(); return b.lastErr }
func (b *protectedBackend) snapshot() (acquires, releases, retains int, installed bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.acquires, b.releases, b.retains, b.installed
}

func killSwitchConfig() SessionConfig {
	c := testConfig()
	c.KillSwitch = true
	return c
}

func awaitHeld(t *testing.T, e *Engine) Status {
	t.Helper()
	ctx := testDeadline(t)
	for {
		if s := e.Status(); s.State == Failed && s.KillSwitch == KillSwitchHolding {
			return s
		}
		select {
		case <-ctx.Done():
			t.Fatal("protection not held", e.Status())
		case <-time.After(time.Millisecond):
		}
	}
}

// With a kill switch, protection is held through the initial attempts and in
// Failed, and only an explicit Stop releases it.
func TestKillSwitchHeldAfterInitialFailure(t *testing.T) {
	var opens atomic.Int32
	b := &protectedBackend{fakeBackend: fakeBackend{open: func(context.Context) (session, error) {
		opens.Add(1)
		return nil, fault("transport_check_failed", true)
	}}}
	e := testEngine(b)
	ctx := testDeadline(t)
	if err := e.Start(ctx, killSwitchConfig()); err != nil {
		t.Fatal(err)
	}
	s := awaitHeld(t, e)
	if s.LastError != "transport_check_failed" || s.ReconnectAttempt != 3 || opens.Load() != 4 || s.Session == nil || !s.Session.Active {
		t.Fatal(s, opens.Load())
	}
	waitCtx, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()
	if err := e.Wait(waitCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("held run ended", err)
	}
	if _, releases, _, installed := b.snapshot(); releases != 0 || !installed {
		t.Fatal("protection released before stop")
	}
	if err := e.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if _, releases, retains, installed := b.snapshot(); releases != 1 || retains != 0 || installed {
		t.Fatal("stop did not release protection", releases, retains, installed)
	}
	if s := e.Status(); s.State != Disconnected || s.KillSwitch != "" {
		t.Fatal(s)
	}
}

func TestKillSwitchHeldAfterPermanentStartupFailure(t *testing.T) {
	b := &protectedBackend{fakeBackend: fakeBackend{open: func(context.Context) (session, error) {
		return nil, fault("access_key_unavailable", false)
	}}}
	e := testEngine(b)
	ctx := testDeadline(t)
	if err := e.Start(ctx, killSwitchConfig()); err != nil {
		t.Fatal(err)
	}
	if s := awaitHeld(t, e); s.LastError != "access_key_unavailable" {
		t.Fatal(s)
	}
	if err := e.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if _, releases, _, installed := b.snapshot(); releases != 1 || installed {
		t.Fatal(releases, installed)
	}
}

// Protection belongs to the run: close/open retries never release it, and the
// status marker distinguishes active protection from held protection.
func TestKillSwitchSpansRetriesAndMarksStatus(t *testing.T) {
	var opens atomic.Int32
	b := &protectedBackend{}
	b.open = func(context.Context) (session, error) {
		n := opens.Add(1)
		if _, releases, _, _ := b.snapshot(); releases != 0 {
			t.Error("protection released between attempts")
		}
		switch {
		case n == 1:
			return fakeSession{wait: func(context.Context) error { return fault("tunnel_adapter_lost", false) }}, nil
		case n < 5:
			return nil, fault("transport_check_failed", true)
		}
		return fakeSession{}, nil
	}
	e := testEngine(b)
	ctx := testDeadline(t)
	if err := e.Start(ctx, killSwitchConfig()); err != nil {
		t.Fatal(err)
	}
	events := eventsUntil(t, e, func(ev Event) bool { return ev.Code == "state" && ev.State == Connected && opens.Load() == 5 })
	for _, ev := range events {
		if ev.Code == "state" && ev.State == Connecting {
			continue // published by Start, before Acquire installs protection
		}
		want := KillSwitchHolding
		if ev.State == Connected {
			want = KillSwitchActive
		}
		if ev.KillSwitch != want {
			t.Fatal(ev)
		}
	}
	if s := e.Status(); s.KillSwitch != KillSwitchActive {
		t.Fatal(s)
	}
	if err := e.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if _, releases, _, installed := b.snapshot(); releases != 1 || installed {
		t.Fatal(releases, installed)
	}
}

func TestKillSwitchReconnectNowRetriesHeldSession(t *testing.T) {
	var opens atomic.Int32
	b := &protectedBackend{fakeBackend: fakeBackend{open: func(context.Context) (session, error) {
		if opens.Add(1) <= 4 {
			return nil, fault("transport_check_failed", true)
		}
		return fakeSession{}, nil
	}}}
	e := testEngine(b)
	ctx := testDeadline(t)
	if err := e.Start(ctx, killSwitchConfig()); err != nil {
		t.Fatal(err)
	}
	awaitHeld(t, e)
	if err := e.ReconnectNow(); err != nil {
		t.Fatal(err)
	}
	awaitStatus(t, e, func(s Status) bool { return s.State == Connected })
	if s := e.Status(); s.KillSwitch != KillSwitchActive || s.ReconnectAttempt != 0 || opens.Load() != 5 {
		t.Fatal(s)
	}
	if acquires, releases, _, _ := b.snapshot(); acquires != 1 || releases != 0 {
		t.Fatal("retry reacquired protection", acquires, releases)
	}
	if err := e.Stop(ctx); err != nil {
		t.Fatal(err)
	}
}

// Start replaces a held session without releasing protection when the new
// profile keeps a kill switch, and refuses a profile that would drop it.
func TestKillSwitchHandover(t *testing.T) {
	var opens atomic.Int32
	b := &protectedBackend{fakeBackend: fakeBackend{open: func(context.Context) (session, error) {
		if opens.Add(1) <= 4 {
			return nil, fault("access_key_unavailable", false)
		}
		return fakeSession{}, nil
	}}}
	e := testEngine(b)
	ctx := testDeadline(t)
	if err := e.Start(ctx, killSwitchConfig()); err != nil {
		t.Fatal(err)
	}
	awaitHeld(t, e)
	if err := e.Start(ctx, testConfig()); !errors.Is(err, ErrKillSwitchHeld) {
		t.Fatal("profile without kill switch replaced held protection", err)
	}
	if s := e.Status(); s.State != Failed || s.KillSwitch != KillSwitchHolding {
		t.Fatal(s)
	}
	opens.Store(4)
	if err := e.Start(ctx, killSwitchConfig()); err != nil {
		t.Fatal(err)
	}
	awaitStatus(t, e, func(s Status) bool { return s.State == Connected })
	if acquires, releases, retains, installed := b.snapshot(); acquires != 2 || releases != 1 || retains != 1 || !installed {
		t.Fatal("handover released protection", acquires, releases, retains, installed)
	}
	if err := e.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if _, _, _, installed := b.snapshot(); installed {
		t.Fatal("stop after handover kept protection")
	}
}

func TestKillSwitchCleanupFailureRetainsProtection(t *testing.T) {
	b := &protectedBackend{fakeBackend: fakeBackend{open: func(context.Context) (session, error) {
		return nil, fault("cleanup_failed_run_recover", false)
	}}}
	e := testEngine(b)
	ctx := testDeadline(t)
	if err := e.Start(ctx, killSwitchConfig()); err != nil {
		t.Fatal(err)
	}
	if err := e.Wait(ctx); err == nil || err.Error() != "cleanup_failed_run_recover" {
		t.Fatal(err)
	}
	if _, releases, retains, installed := b.snapshot(); releases != 1 || retains != 1 || !installed {
		t.Fatal(releases, retains, installed)
	}
}

func TestKillSwitchReleaseFailureIsVisible(t *testing.T) {
	b := &protectedBackend{fakeBackend: fakeBackend{open: func(context.Context) (session, error) { return fakeSession{}, nil }}, releaseErr: errors.New("wfp")}
	e := testEngine(b)
	ctx := testDeadline(t)
	if err := e.Start(ctx, killSwitchConfig()); err != nil {
		t.Fatal(err)
	}
	awaitStatus(t, e, func(s Status) bool { return s.State == Connected })
	if err := e.Stop(ctx); err == nil || err.Error() != "cleanup_failed_run_recover" {
		t.Fatal(err)
	}
	if s := e.Status(); s.State != Failed || s.LastError != "cleanup_failed_run_recover" {
		t.Fatal(s)
	}
}

// Native IKEv2 keeps the bounded policy after an established session is lost.
func TestRecoveryCyclesExcludeIKEv2(t *testing.T) {
	e := testEngine(fakeBackend{})
	e.events = make(chan Event, 16)
	e.recovery = recovery{cycles: false, established: true}
	e.status.State = Connected
	e.mu.Lock()
	for range initialRetryLimit {
		if _, _, ok := e.scheduleLocked(fault("network_changed", true)); !ok {
			t.Fatal("budget exhausted early")
		}
	}
	_, _, ok := e.scheduleLocked(fault("network_changed", true))
	e.mu.Unlock()
	if ok || e.recoverable(fault("access_key_unavailable", false)) {
		t.Fatal("IKEv2 entered recovery cycles")
	}
}
