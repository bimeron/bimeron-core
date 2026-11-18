package core

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"
)

type failingRecovery struct {
	fakeSession
	retries atomic.Int32
}

func (s *failingRecovery) Wait(context.Context) error { return fault("network_changed", true) }
func (s *failingRecovery) Suspend()                   {}
func (s *failingRecovery) Reconnect(context.Context) error {
	s.retries.Add(1)
	return fault("transport_check_failed", true)
}

// The initial connection is bounded: the first attempt plus three retries.
func TestReconnectBudgetExhaustion(t *testing.T) {
	var opens atomic.Int32
	e := testEngine(fakeBackend{open: func(context.Context) (session, error) {
		opens.Add(1)
		return nil, fault("transport_check_failed", true)
	}})
	ctx := testDeadline(t)
	if err := e.Start(ctx, testConfig()); err != nil {
		t.Fatal(err)
	}
	if err := e.Wait(ctx); err == nil {
		t.Fatal("missing terminal error")
	}
	status := e.Status()
	if status.State != Failed || status.LastError != "transport_check_failed" || status.LastErrorPermanent || status.ReconnectAttempt != 3 || status.ReconnectLimit != 3 {
		t.Fatal(status)
	}
	if status.ReconnectCycle != 0 || status.ReconnectPhase != "" || !status.NextAttemptAt.IsZero() || status.KillSwitch != "" {
		t.Fatal("initial attempts published recovery cycle fields", status)
	}
	// A later Stop (daemon shutdown, CLI stop) reports only teardown.
	if err := e.Stop(ctx); err != nil {
		t.Fatal("stop after terminal failure", err)
	}
	if again := e.Status(); again.State != Failed || again.LastError != "transport_check_failed" {
		t.Fatal("stop changed terminal status", again)
	}
	if opens.Load() != 4 || status.Attempt != 4 {
		t.Fatal("expected initial + three retries", opens.Load(), status)
	}
	progress := []int{}
	for len(e.Events()) > 0 {
		ev := <-e.Events()
		if ev.Code == "reconnect_attempt" {
			data, err := json.Marshal(ev)
			if err != nil {
				t.Fatal(err)
			}
			var wire map[string]any
			if err := json.Unmarshal(data, &wire); err != nil {
				t.Fatal(err)
			}
			if wire["ReconnectAttempt"] != float64(ev.ReconnectAttempt) || wire["ReconnectLimit"] != float64(3) || wire["ReconnectPhase"] != PhaseAttempting || wire["NextAttemptAt"] == nil {
				t.Fatal(string(data))
			}
			if _, present := wire["ReconnectCycle"]; present {
				t.Fatal(string(data))
			}
			progress = append(progress, ev.ReconnectAttempt)
			if ev.ReconnectLimit != 3 || ev.LastError == "" {
				t.Fatal(ev)
			}
		}
	}
	if len(progress) != 3 || progress[0] != 1 || progress[1] != 2 || progress[2] != 3 {
		t.Fatal(progress)
	}
	data, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(data, &wire); err != nil {
		t.Fatal(err)
	}
	if wire["ReconnectAttempt"] != float64(3) || wire["ReconnectLimit"] != float64(3) {
		t.Fatal(string(data))
	}
	for _, field := range []string{"ReconnectCycle", "ReconnectPhase", "NextAttemptAt", "KillSwitch"} {
		if _, present := wire[field]; present {
			t.Fatal(field, string(data))
		}
	}
}

// A cleanup failure while an established session recovers ends the run and
// stays visible to a later Stop.
func TestCleanupFailureDuringRecoveryIsTerminal(t *testing.T) {
	p := &failingRecovery{fakeSession: fakeSession{close: func() error { return fault("cleanup_failed_run_recover", false) }}}
	e := testEngine(fakeBackend{open: func(context.Context) (session, error) { return p, nil }})
	e.opts.CyclePause = time.Hour
	ctx := testDeadline(t)
	if err := e.Start(ctx, testConfig()); err != nil {
		t.Fatal(err)
	}
	for e.Status().ReconnectPhase != PhaseWaiting {
		time.Sleep(time.Millisecond)
	}
	if p.retries.Load() != cycleAttemptLimit {
		t.Fatal("cycle length", p.retries.Load())
	}
	if err := e.Stop(ctx); err == nil || err.Error() != "cleanup_failed_run_recover" {
		t.Fatal(err)
	}
	if s := e.Status(); s.State != Failed || s.LastError != "cleanup_failed_run_recover" {
		t.Fatal(s)
	}
}

func TestReconnectBudgetResetsAfterSuccess(t *testing.T) {
	var opens atomic.Int32
	e := testEngine(fakeBackend{open: func(context.Context) (session, error) {
		n := opens.Add(1)
		if n == 1 || n == 4 {
			return fakeSession{wait: func(context.Context) error { return fault("network_changed", true) }}, nil
		}
		if n == 7 {
			return fakeSession{}, nil
		}
		return nil, fault("transport_check_failed", true)
	}})
	ctx := testDeadline(t)
	if err := e.Start(ctx, testConfig()); err != nil {
		t.Fatal(err)
	}
	awaitState(t, e, Reconnecting)
	awaitState(t, e, Connected)
	awaitState(t, e, Reconnecting)
	awaitState(t, e, Connected)
	if s := e.Status(); s.ReconnectAttempt != 0 || s.ReconnectLimit != 0 {
		t.Fatal(s)
	}
	if err := e.Stop(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestStopDuringReconnectBackoffClearsProgress(t *testing.T) {
	var opens atomic.Int32
	e := testEngine(fakeBackend{open: func(context.Context) (session, error) {
		opens.Add(1)
		return nil, fault("transport_check_failed", true)
	}})
	e.opts.RetryMin = time.Hour
	ctx := testDeadline(t)
	if err := e.Start(ctx, testConfig()); err != nil {
		t.Fatal(err)
	}
	awaitState(t, e, Reconnecting)
	if s := e.Status(); s.ReconnectAttempt != 1 || s.ReconnectLimit != 3 {
		t.Fatal(s)
	}
	if err := e.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if s := e.Status(); s.State != Disconnected || s.ReconnectAttempt != 0 || s.ReconnectLimit != 0 || opens.Load() != 1 {
		t.Fatal(s, opens.Load())
	}
	data, err := json.Marshal(e.Status())
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(data, &wire); err != nil {
		t.Fatal(err)
	}
	if _, present := wire["ReconnectAttempt"]; present {
		t.Fatal(string(data))
	}
}

func TestUnexpectedSessionEndRecovers(t *testing.T) {
	var opens atomic.Int32
	e := testEngine(fakeBackend{open: func(context.Context) (session, error) {
		if opens.Add(1) == 1 {
			return fakeSession{wait: func(context.Context) error { return nil }}, nil
		}
		return fakeSession{}, nil
	}})
	ctx := testDeadline(t)
	if err := e.Start(ctx, testConfig()); err != nil {
		t.Fatal(err)
	}
	awaitState(t, e, Reconnecting)
	if s := e.Status(); s.LastError != "session_stopped_unexpectedly" {
		t.Fatal(s)
	}
	awaitState(t, e, Connected)
	if err := e.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if s := e.Status(); s.State != Disconnected || opens.Load() != 2 {
		t.Fatal(s, opens.Load())
	}
}
