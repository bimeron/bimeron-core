package core

import (
	"context"
	"errors"
	"testing"

	"bimeron/internal/telemetry"
)

// Separate reads can pair an earlier session's counters with a later identity.
func TestStatsAndStatusCanStraddleSessions(t *testing.T) {
	ctx := testDeadline(t)
	writes := []int64{17, 29}
	e := New(Options{})
	e.factory = func(cfg SessionConfig) backend {
		bytes := writes[0]
		writes = writes[1:]
		return fakeBackend{open: func(context.Context) (session, error) {
			cfg.stats.Sent(bytes)
			return fakeSession{}, nil
		}}
	}
	t.Cleanup(func() { _ = e.Stop(ctx) })
	if err := e.Start(ctx, testConfig()); err != nil {
		t.Fatal(err)
	}
	awaitState(t, e, Connected)
	oldID := e.Status().Session.ID

	sampled := make(chan struct{})
	resume := make(chan struct{})
	type reading struct {
		stats  telemetry.Snapshot
		status Status
	}
	result := make(chan reading, 1)
	go func() {
		stats := e.Stats()
		close(sampled)
		select {
		case <-resume:
			result <- reading{stats: stats, status: e.Status()}
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
	if err := e.Start(ctx, testConfig()); err != nil {
		t.Fatal(err)
	}
	awaitState(t, e, Connected)
	newID := e.Status().Session.ID
	if newID == oldID || e.Stats().BytesUp != 29 {
		t.Fatalf("second session: %+v, %+v", e.Status(), e.Stats())
	}
	close(resume)
	select {
	case got := <-result:
		if got.stats.BytesUp != 17 || got.status.Session.ID != newID {
			t.Fatalf("expected old counters paired with new identity: %+v", got)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestStatsAcceptedStartIsolation(t *testing.T) {
	ctx := testDeadline(t)
	entered := make(chan SessionConfig, 1)
	resume := make(chan struct{})
	e := New(Options{})
	e.factory = func(cfg SessionConfig) backend {
		entered <- cfg
		select {
		case <-resume:
			cfg.stats.Sent(5)
		case <-ctx.Done():
		}
		return fakeBackend{openConfig: func(_ context.Context, opened SessionConfig) (session, error) {
			if opened.stats != cfg.stats || opened.stats.Snapshot().BytesUp != 5 {
				t.Error("Open did not receive factory counters")
			}
			opened.stats.Sent(12)
			return fakeSession{}, nil
		}}
	}
	t.Cleanup(func() { _ = e.Stop(ctx) })
	var previous *telemetry.Counters
	for cycle := 0; cycle < 2; cycle++ {
		if err := e.Start(ctx, testConfig()); err != nil {
			t.Fatal(err)
		}
		var cfg SessionConfig
		select {
		case cfg = <-entered:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		if got := e.Stats().BytesUp; got != 0 {
			t.Fatalf("accepted Start retained %d bytes before factory writes", got)
		}
		if previous != nil {
			previous.Sent(100)
			if got := e.Stats().BytesUp; got != 0 {
				t.Fatalf("stale counters contaminated new session: %d", got)
			}
		}
		select {
		case resume <- struct{}{}:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		awaitState(t, e, Connected)
		if got := e.Stats().BytesUp; got != 17 {
			t.Fatalf("factory/Open writes: %d", got)
		}
		if err := e.Start(ctx, testConfig()); !errors.Is(err, ErrSessionRunning) {
			t.Fatalf("active Start: %v", err)
		}
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		if err := e.Start(cancelled, testConfig()); !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled Start: %v", err)
		}
		if got := e.Stats().BytesUp; got != 17 {
			t.Fatalf("rejected Start reset counters: %d", got)
		}
		if err := e.Stop(ctx); err != nil {
			t.Fatal(err)
		}
		if got := e.Stats().BytesUp; got != 17 {
			t.Fatalf("Stop lost counters: %d", got)
		}
		previous = cfg.stats
	}
}
