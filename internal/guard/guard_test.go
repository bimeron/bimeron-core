package guard

import (
	"bytes"
	"os"
	"os/exec"
	"testing"
	"time"
)

func capture(t *testing.T) <-chan any {
	t.Helper()
	got := make(chan any, 4)
	t.Cleanup(SetRethrow(func(p any) { got <- p }))
	return got
}

func receive(t *testing.T, got <-chan any) any {
	t.Helper()
	select {
	case p := <-got:
		return p
	case <-time.After(5 * time.Second):
		t.Fatal("panic was not rethrown")
		return nil
	}
}

func TestWithoutHandlersPanicIsRethrown(t *testing.T) {
	got := capture(t)
	Go(func() { panic("boom") })
	if p := receive(t, got); p != "boom" {
		t.Fatal(p)
	}
}

func TestHandlerRunsBeforeRethrow(t *testing.T) {
	got := capture(t)
	cleaned := make(chan struct{})
	seen := make(chan any, 1)
	unregister := Register(func(p any) <-chan struct{} {
		seen <- p
		go func() { time.Sleep(20 * time.Millisecond); close(cleaned) }()
		return cleaned
	})
	defer unregister()
	Go(func() { panic("relay") })
	if p := receive(t, got); p != "relay" {
		t.Fatal(p)
	}
	select {
	case <-cleaned:
	default:
		t.Fatal("rethrown before cleanup finished")
	}
	if p := <-seen; p != "relay" {
		t.Fatal(p)
	}
}

func TestDeferredCleanupRunsBeforeHandoff(t *testing.T) {
	got := capture(t)
	order := make(chan string, 2)
	unregister := Register(func(any) <-chan struct{} {
		order <- "handler"
		done := make(chan struct{})
		close(done)
		return done
	})
	defer unregister()
	go func() {
		defer Recover()
		defer func() { order <- "deferred" }()
		panic("x")
	}()
	receive(t, got)
	if first := <-order; first != "deferred" {
		t.Fatal("goroutine cleanup ran after the handoff")
	}
}

func TestStuckCleanupTimesOut(t *testing.T) {
	got := capture(t)
	mu.Lock()
	timeout = 50 * time.Millisecond
	mu.Unlock()
	t.Cleanup(func() { mu.Lock(); timeout = CleanupTimeout; mu.Unlock() })
	unregister := Register(func(any) <-chan struct{} { return make(chan struct{}) })
	defer unregister()
	start := time.Now()
	Go(func() { panic("stuck") })
	if p := receive(t, got); p != "stuck" {
		t.Fatal(p)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("timeout not applied")
	}
}

func TestUnregisterRemovesHandler(t *testing.T) {
	got := capture(t)
	called := false
	unregister := Register(func(any) <-chan struct{} {
		called = true
		done := make(chan struct{})
		close(done)
		return done
	})
	unregister()
	Go(func() { panic("late") })
	receive(t, got)
	if called {
		t.Fatal("unregistered handler was called")
	}
}

func TestNoPanicIsNoop(t *testing.T) {
	got := capture(t)
	done := make(chan struct{})
	Go(func() { close(done) })
	<-done
	select {
	case p := <-got:
		t.Fatal("rethrown without a panic", p)
	case <-time.After(20 * time.Millisecond):
	}
}

//go:noinline
func panicAtTracebackOrigin() { panic("traceback sentinel") }

func TestOriginalPanicTraceback(t *testing.T) {
	if os.Getenv("BIMERON_GUARD_TRACEBACK_CHILD") == "1" {
		done := make(chan struct{})
		close(done)
		Register(func(any) <-chan struct{} { return done })
		Go(panicAtTracebackOrigin)
		select {}
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestOriginalPanicTraceback$")
	cmd.Env = append(os.Environ(), "BIMERON_GUARD_TRACEBACK_CHILD=1", "GOTRACEBACK=single")
	out, err := cmd.CombinedOutput()
	if err == nil || !bytes.Contains(out, []byte("panic: traceback sentinel")) || !bytes.Contains(out, []byte("guard.panicAtTracebackOrigin()")) {
		t.Fatalf("missing original panic frame: %v\n%s", err, out)
	}
}

func TestStopCannotCommitAfterPanicDispatch(t *testing.T) {
	got := capture(t)
	entered, resume := make(chan struct{}), make(chan struct{})
	_, commit, unregister := RegisterSession(func(any) <-chan struct{} {
		close(entered)
		<-resume
		return resume
	})
	defer unregister()
	Go(func() { panic("during stop") })
	<-entered
	committed := commit()
	close(resume)
	receive(t, got)
	if committed {
		t.Fatal("normal stop committed during crash dispatch")
	}
}
