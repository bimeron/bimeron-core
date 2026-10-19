package core

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
)

func TestConcurrentStartAndStatsLifecycle(t *testing.T) {
	e := New(Options{})
	e.factory = func(c SessionConfig) backend {
		if c.stats == nil {
			t.Error("missing session counters")
		}
		h := directHandler(context.Background(), c, networkPath{}, func(string, string) {}, nil)
		if h.Stats != c.stats {
			t.Error("handler counters not shared")
		}
		h.Stats.Sent(17)
		h.Close()
		return fakeBackend{open: func(context.Context) (session, error) { return fakeSession{}, nil }}
	}
	ctx := testDeadline(t)
	defer e.Stop(context.Background())
	var wg sync.WaitGroup
	var accepted atomic.Int32
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if e.Start(ctx, testConfig()) == nil {
				accepted.Add(1)
			}
			_ = e.Status()
			_ = e.Stats()
		}()
	}
	wg.Wait()
	if accepted.Load() != 1 {
		t.Fatalf("accepted %d parallel starts", accepted.Load())
	}
	awaitState(t, e, Connected)
	if e.Stats().BytesUp != 17 {
		t.Fatal("statistics not propagated", e.Stats())
	}
	if err := e.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if e.Stats().BytesUp != 17 {
		t.Fatal("statistics lost after stop")
	}
	if err := e.Start(ctx, testConfig()); err != nil {
		t.Fatal(err)
	}
	awaitState(t, e, Connected)
	if e.Stats().BytesUp != 17 {
		t.Fatal("statistics not reset for next session", e.Stats())
	}
}
