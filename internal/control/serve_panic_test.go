package control

import (
	"context"
	"net"
	"testing"
	"time"

	"bimeron/core"
	"bimeron/internal/guard"
)

// crashedEngine behaves like a real engine whose run took the crash path:
// Stop waits for a run that never finishes.
type crashedEngine struct {
	abandonEngine
	stopping chan struct{}
	release  chan struct{}
}

func (e *crashedEngine) Stop(context.Context) error {
	select {
	case e.stopping <- struct{}{}:
	default:
	}
	<-e.release
	return nil
}

func serveUntilPanic(t *testing.T, s *Server, l panickingListener) <-chan any {
	t.Helper()
	result := make(chan any, 1)
	go func() {
		defer func() { result <- recover() }()
		_ = s.Serve(context.Background(), l)
	}()
	return result
}

// A listener panic must leave Serve even while a request handler is blocked
// in Stop on the crashed session.
func TestServeListenerPanicDoesNotWaitForCrashedSession(t *testing.T) {
	e := &crashedEngine{
		abandonEngine: abandonEngine{fakeEngine: fakeEngine{state: core.Connected, events: make(chan core.Event)}},
		stopping:      make(chan struct{}, 1),
		release:       make(chan struct{}),
	}
	defer close(e.release)
	defer guard.Register(func(any) <-chan struct{} {
		done := make(chan struct{})
		close(done)
		return done
	})()
	s := NewServer(e)
	l := panickingListener{scriptedListener{conns: make(chan net.Conn), fail: make(chan struct{})}}
	result := serveUntilPanic(t, s, l)

	client, server := net.Pipe()
	defer client.Close()
	l.conns <- server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() { _, _ = exchange(ctx, client, Request{Command: "stop"}) }()
	select {
	case <-e.stopping:
	case <-ctx.Done():
		t.Fatal("stop request did not reach the engine")
	}
	close(l.fail)
	select {
	case p := <-result:
		if p != "accept" {
			t.Fatal(p)
		}
	case <-ctx.Done():
		t.Fatal("listener panic waited for the crashed session")
	}
}

// Without a registered session the panic leaves Serve at once.
func TestServeListenerPanicWithoutSession(t *testing.T) {
	waitNoSessions(t)
	e := &abandonEngine{fakeEngine: fakeEngine{state: core.Disconnected, events: make(chan core.Event)}}
	s := NewServer(e)
	l := panickingListener{scriptedListener{conns: make(chan net.Conn), fail: make(chan struct{})}}
	result := serveUntilPanic(t, s, l)
	close(l.fail)
	select {
	case p := <-result:
		if p != "accept" || e.marked || e.stopped {
			t.Fatal(p, e.marked, e.stopped)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("listener panic stalled")
	}
}

func waitNoSessions(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for guard.Active() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("a session handler from another test is still registered")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
