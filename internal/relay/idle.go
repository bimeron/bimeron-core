// Package relay holds helpers shared by the TCP relays of the system VPN
// handler and the local SOCKS5 proxy.
package relay

import (
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// Idle limits for relayed TCP flows. A flow with no data in either direction
// for IdleTimeout is closed; once one direction has finished, the remaining
// direction may be idle for HalfClosedIdleTimeout. The limits release relay
// slots held by peers that stop sending; applications that keep long idle
// connections should enable keepalives.
const (
	IdleTimeout           = 10 * time.Minute
	HalfClosedIdleTimeout = time.Minute
)

// checksPerLimit sets the watchdog resolution: a flow is closed after
// between limit and limit·(1+1/checksPerLimit) without data.
const checksPerLimit = 4

// Watchdog closes a relayed flow when no data has been written in either
// direction for the current limit. It costs one timer per flow and one atomic
// store per write.
type Watchdog struct {
	active atomic.Bool
	mu     sync.Mutex
	limit  time.Duration
	idle   time.Duration
	timer  *time.Timer
	close  func()
	done   bool
}

// Watch starts a watchdog that calls closeFlow once after limit without data.
func Watch(limit time.Duration, closeFlow func()) *Watchdog {
	w := &Watchdog{limit: limit, close: closeFlow}
	w.mu.Lock()
	w.timer = time.AfterFunc(w.period(), w.check)
	w.mu.Unlock()
	return w
}

func (w *Watchdog) period() time.Duration {
	if p := w.limit / checksPerLimit; p > 0 {
		return p
	}
	return time.Nanosecond
}

func (w *Watchdog) check() {
	w.mu.Lock()
	if w.done {
		w.mu.Unlock()
		return
	}
	if w.active.Swap(false) {
		w.idle = 0
	} else {
		w.idle += w.period()
	}
	if w.idle < w.limit {
		w.timer.Reset(w.period())
		w.mu.Unlock()
		return
	}
	w.done = true
	closeFlow := w.close
	w.mu.Unlock()
	closeFlow()
}

// SetLimit changes the idle limit, for example after a half-close. Time
// already spent idle counts toward the new limit.
func (w *Watchdog) SetLimit(limit time.Duration) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.done || limit == w.limit {
		return
	}
	w.limit = limit
	if w.idle >= limit {
		w.idle = limit - w.period()
	}
	w.timer.Reset(w.period())
}

// Stop ends the watchdog without closing the flow.
func (w *Watchdog) Stop() {
	w.mu.Lock()
	w.done = true
	w.timer.Stop()
	w.mu.Unlock()
}

// Writer marks the flow active on every successful write to dst. It keeps
// only io.Writer, so a source's io.WriterTo fast path still applies.
func (w *Watchdog) Writer(dst io.Writer) io.Writer { return activeWriter{dst, w} }

type activeWriter struct {
	io.Writer
	w *Watchdog
}

func (a activeWriter) Write(p []byte) (int, error) {
	n, err := a.Writer.Write(p)
	if n > 0 {
		a.w.active.Store(true)
	}
	return n, err
}
