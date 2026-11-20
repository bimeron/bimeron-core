// Package guard is the panic boundary for goroutines that Core starts.
//
// A goroutine root defers Recover. Without an active session, a recovered
// panic is rethrown unchanged, as if there were no boundary. With a session,
// the panic is handed to every registered handler, which runs the session's
// crash cleanup (kill switch protection is kept, other network state is
// released). The panicking goroutine waits for that, at most CleanupTimeout,
// and then rethrows the original panic, which ends the process.
//
// Covered: goroutine roots that Core starts for flows, DNS, transport read
// loops, control workers and SOCKS UDP association cleanup. Not covered: other timer and context.AfterFunc
// callbacks and goroutines inside third-party libraries.
package guard

import (
	"sync"
	"time"
)

// CleanupTimeout bounds how long a recovered panic waits for session cleanup
// before the process is ended anyway.
const CleanupTimeout = 30 * time.Second

// Handler starts crash cleanup for one session and returns a channel that is
// closed when the cleanup has finished. It must not block.
type Handler func(panicValue any) <-chan struct{}

var (
	mu       sync.Mutex
	handlers = map[*registration]struct{}{}
	// rethrow ends the process; tests replace it.
	rethrow = func(p any) { panic(p) }
	timeout = CleanupTimeout
)

type registration struct {
	handler    Handler
	dispatched bool
}

// Register adds a crash handler until the returned function is called.
func Register(h Handler) func() {
	_, _, unregister := RegisterSession(h)
	return unregister
}

// RegisterSession exposes a synchronized crash check without committing cleanup.
// Its commit function commits normal cleanup only if
// no panic has claimed the session. A successful commit removes the handler.
func RegisterSession(h Handler) (crashClaimed, commitStop func() bool, unregister func()) {
	key := &registration{handler: h}
	mu.Lock()
	handlers[key] = struct{}{}
	mu.Unlock()
	commitStop = func() bool {
		mu.Lock()
		defer mu.Unlock()
		if key.dispatched {
			return false
		}
		delete(handlers, key)
		return true
	}
	unregister = func() {
		mu.Lock()
		delete(handlers, key)
		mu.Unlock()
	}
	crashClaimed = func() bool {
		mu.Lock()
		defer mu.Unlock()
		return key.dispatched
	}
	return crashClaimed, commitStop, unregister
}

// Active reports how many handlers are registered. Tests use it to check
// that no session is left running.
func Active() int {
	mu.Lock()
	defer mu.Unlock()
	return len(handlers)
}

// Go runs fn in a new goroutine under the panic boundary.
func Go(fn func()) {
	go func() {
		defer Recover()
		fn()
	}()
}

// CloseOnExit closes a relay stream synchronously on normal return. During
// panic unwinding a transport close must not hold up the goroutine's boundary.
func CloseOnExit(closeStream func()) {
	if p := recover(); p != nil {
		Go(closeStream)
		panic(p)
	}
	closeStream()
}

// Recover must be deferred directly by the goroutine root, as the first
// deferred call, so the goroutine's own deferred cleanup runs first. The
// control server's Serve is the one exception: it defers Recover inside its
// own shutdown handler, which then only releases the listener and rethrows.
func Recover() {
	p := recover()
	if p == nil {
		return
	}
	// Rethrowing here, inside the deferred call, keeps the original frames in
	// the crash traceback.
	handle(p)
}

func handle(p any) {
	mu.Lock()
	active := make([]Handler, 0, len(handlers))
	for h := range handlers {
		h.dispatched = true
		active = append(active, h.handler)
	}
	rethrow, timeout := rethrow, timeout
	mu.Unlock()
	if len(active) == 0 {
		rethrow(p)
		return
	}
	done := make([]<-chan struct{}, 0, len(active))
	for _, h := range active {
		done = append(done, h(p))
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for _, d := range done {
		select {
		case <-d:
		case <-deadline.C:
			rethrow(p)
			return
		}
	}
	// Every session finished its crash cleanup; end the process.
	rethrow(p)
}

// SetRethrow replaces how a recovered panic ends the process and returns a
// function that restores it. Only tests outside this package use it.
func SetRethrow(f func(any)) (restore func()) {
	mu.Lock()
	previous := rethrow
	rethrow = f
	mu.Unlock()
	return func() {
		mu.Lock()
		rethrow = previous
		mu.Unlock()
	}
}
