package relay

import (
	"io"
	"sync/atomic"
	"testing"
	"time"
)

func waitClosed(t *testing.T, closed <-chan struct{}, within time.Duration) {
	t.Helper()
	select {
	case <-closed:
	case <-time.After(within):
		t.Fatal("idle flow was not closed")
	}
}

func TestWatchdogClosesIdleFlow(t *testing.T) {
	closed := make(chan struct{})
	start := time.Now()
	w := Watch(40*time.Millisecond, func() { close(closed) })
	defer w.Stop()
	waitClosed(t, closed, 2*time.Second)
	if elapsed := time.Since(start); elapsed < 40*time.Millisecond {
		t.Fatal("closed before the limit:", elapsed)
	}
}

func TestWatchdogKeepsActiveFlow(t *testing.T) {
	var closed atomic.Bool
	w := Watch(60*time.Millisecond, func() { closed.Store(true) })
	defer w.Stop()
	writer := w.Writer(io.Discard)
	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) {
		if _, err := writer.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if closed.Load() {
		t.Fatal("active flow was closed")
	}
}

func TestWatchdogEmptyWritesAreNotActivity(t *testing.T) {
	closed := make(chan struct{})
	w := Watch(40*time.Millisecond, func() { close(closed) })
	defer w.Stop()
	writer := w.Writer(io.Discard)
	stop := time.After(2 * time.Second)
	for {
		_, _ = writer.Write(nil)
		select {
		case <-closed:
			return
		case <-stop:
			t.Fatal("empty writes kept the flow open")
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func TestWatchdogStopPreventsClose(t *testing.T) {
	var closed atomic.Bool
	w := Watch(20*time.Millisecond, func() { closed.Store(true) })
	w.Stop()
	time.Sleep(100 * time.Millisecond)
	if closed.Load() {
		t.Fatal("stopped watchdog closed the flow")
	}
}

func TestWatchdogSetLimitShortens(t *testing.T) {
	closed := make(chan struct{})
	w := Watch(time.Hour, func() { close(closed) })
	defer w.Stop()
	start := time.Now()
	w.SetLimit(40 * time.Millisecond)
	waitClosed(t, closed, 2*time.Second)
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatal("shortened limit took", elapsed)
	}
	w.SetLimit(time.Hour) // after close: no effect, no panic
}
