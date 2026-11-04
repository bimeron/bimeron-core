package core

import (
	"context"
	"testing"
)

func TestStatsSnapshotSessionLifecycle(t *testing.T) {
	ctx := testDeadline(t)
	entered := make(chan SessionConfig, 1)
	resume := make(chan struct{})
	e := New(Options{})
	e.factory = func(cfg SessionConfig) backend {
		entered <- cfg
		select {
		case <-resume:
		case <-ctx.Done():
		}
		return fakeBackend{openConfig: func(_ context.Context, c SessionConfig) (session, error) {
			c.stats.Sent(17)
			return fakeSession{}, nil
		}}
	}
	t.Cleanup(func() { _ = e.Stop(ctx) })
	if got := e.StatsSnapshot(); got.Status.Session != nil || got.Counters != nil {
		t.Fatalf("unstarted snapshot: %+v", got)
	}
	var previous StatsSnapshot
	for i := 0; i < 2; i++ {
		if err := e.Start(ctx, testConfig()); err != nil {
			t.Fatal(err)
		}
		select {
		case <-entered:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		got := e.StatsSnapshot()
		if got.Status.Session == nil || !got.Status.Session.Active || got.Status.State != Connecting || got.Status.Attempt != 0 || got.Counters == nil || got.Counters.BytesUp != 0 {
			t.Fatalf("accepted Start snapshot: %+v", got)
		}
		if i > 0 && (got.Status.Session.ID == previous.Status.Session.ID || previous.Counters.BytesUp != 17 || previous.Status.Session.Active) {
			t.Fatalf("reset/retained snapshot: %+v, %+v", got, previous)
		}
		select {
		case resume <- struct{}{}:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		awaitState(t, e, Connected)
		got = e.StatsSnapshot()
		if got.Counters.BytesUp != 17 || got.Counters.Unavailable || got.Status.State != Connected {
			t.Fatalf("connected snapshot: %+v", got)
		}
		got.Status.Session.ID = "changed"
		got.Counters.BytesUp = 999
		if fresh := e.StatsSnapshot(); fresh.Status.Session.ID == "changed" || fresh.Counters.BytesUp != 17 {
			t.Fatalf("snapshot aliases Engine: %+v", fresh)
		}
		if err := e.Stop(ctx); err != nil {
			t.Fatal(err)
		}
		previous = e.StatsSnapshot()
		if previous.Status.State != Disconnected || previous.Status.Session.Active || previous.Counters.BytesUp != 17 {
			t.Fatalf("terminal snapshot: %+v", previous)
		}
	}
}

func TestStatsSnapshotTransitionBarrier(t *testing.T) {
	ctx := testDeadline(t)
	e := testEngine(fakeBackend{openConfig: func(_ context.Context, c SessionConfig) (session, error) {
		c.stats.Sent(17)
		return fakeSession{}, nil
	}})
	t.Cleanup(func() { _ = e.Stop(ctx) })
	if err := e.Start(ctx, testConfig()); err != nil {
		t.Fatal(err)
	}
	awaitState(t, e, Connected)
	oldID := e.Status().Session.ID
	sampled := make(chan StatsSnapshot, 1)
	resume := make(chan struct{})
	result := make(chan StatsSnapshot, 1)
	go func() {
		snapshot := e.StatsSnapshot()
		sampled <- snapshot
		select {
		case <-resume:
			result <- snapshot
		case <-ctx.Done():
		}
	}()
	select {
	case <-sampled:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if err := e.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	e.factory = func(c SessionConfig) backend {
		return fakeBackend{open: func(context.Context) (session, error) { c.stats.Sent(29); return fakeSession{}, nil }}
	}
	if err := e.Start(ctx, testConfig()); err != nil {
		t.Fatal(err)
	}
	awaitState(t, e, Connected)
	close(resume)
	select {
	case got := <-result:
		if got.Status.Session.ID != oldID || got.Counters.BytesUp != 17 {
			t.Fatalf("captured session changed: %+v", got)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if got := e.StatsSnapshot(); got.Status.Session.ID == oldID || got.Counters.BytesUp != 29 {
		t.Fatalf("new session snapshot: %+v", got)
	}
}

func TestStatsSnapshotNativeUnavailableAndDetached(t *testing.T) {
	ctx := testDeadline(t)
	e := testEngine(fakeBackend{open: func(context.Context) (session, error) { return fakeSession{}, nil }})
	t.Cleanup(func() { _ = e.Stop(ctx) })
	if err := e.Start(ctx, ikev2TestConfig()); err != nil {
		t.Fatal(err)
	}
	awaitState(t, e, Connected)
	got := e.StatsSnapshot()
	if got.Counters == nil || !got.Counters.Unavailable || got.Status.Attempt != 1 || got.Status.Native == nil {
		t.Fatalf("native snapshot: %+v", got)
	}
	cleanup := got.Status.Native.RASCleanup
	got.Status.Native.RASCleanup = "changed"
	got.Status.Session.StatsUnavailable = false
	if fresh := e.StatsSnapshot(); fresh.Status.Native.RASCleanup != cleanup || !fresh.Counters.Unavailable {
		t.Fatalf("native metadata aliases Engine: %+v", fresh)
	}
	if err := e.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if terminal := e.StatsSnapshot(); terminal.Status.Session.Active || terminal.Counters == nil || !terminal.Counters.Unavailable {
		t.Fatalf("native terminal snapshot: %+v", terminal)
	}
}

func TestStatsSnapshotRetryIsCumulative(t *testing.T) {
	ctx := testDeadline(t)
	retry := make(chan struct{})
	opened := make(chan struct{}, 1)
	var opens int
	e := testEngine(fakeBackend{openConfig: func(_ context.Context, c SessionConfig) (session, error) {
		opens++
		if opens == 1 {
			c.stats.Sent(17)
			return fakeSession{wait: func(wait context.Context) error {
				select {
				case <-retry:
					return fault("network_changed", true)
				case <-wait.Done():
					return wait.Err()
				}
			}}, nil
		}
		c.stats.Sent(29)
		opened <- struct{}{}
		return fakeSession{}, nil
	}})
	t.Cleanup(func() { _ = e.Stop(ctx) })
	if err := e.Start(ctx, testConfig()); err != nil {
		t.Fatal(err)
	}
	awaitState(t, e, Connected)
	first := e.StatsSnapshot()
	if first.Status.Attempt != 1 || first.Counters.BytesUp != 17 {
		t.Fatalf("first attempt: %+v", first)
	}
	close(retry)
	select {
	case <-opened:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	awaitState(t, e, Connected)
	second := e.StatsSnapshot()
	if second.Status.Session.ID != first.Status.Session.ID || second.Status.Attempt != 2 || second.Counters.BytesUp != 46 {
		t.Fatalf("retry counters reset: %+v", second)
	}
	if err := e.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if got := e.StatsSnapshot(); got.Status.Session.Active || got.Counters.BytesUp != 46 {
		t.Fatalf("terminal retry counters: %+v", got)
	}
}
