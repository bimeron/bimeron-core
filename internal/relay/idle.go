// Package relay holds helpers shared by the TCP relays of the system VPN
// handler and the local SOCKS5 proxy.
package relay

import (
	"io"
	"sync"
	"time"
)

// Idle limits for relayed TCP flows. A flow with no data in either direction
// for IdleTimeout is closed; once one direction has finished, the remaining
// direction may be idle for HalfClosedIdleTimeout. The limits release relay
// slots held by peers that stop sending; applications that keep long idle
// connections should enable keepalives.
const (
	IdleTimeout           = 30 * time.Minute
	HalfClosedIdleTimeout = time.Minute
)

// Watchdog tracks successful writes in both directions using one timer per flow.
type Watchdog struct {
	mu    sync.Mutex
	limit time.Duration
	last  time.Time
	timer *time.Timer
	close func()
	done  bool
}

// Watch starts a watchdog that calls closeFlow once after limit without data.
func Watch(limit time.Duration, closeFlow func()) *Watchdog {
	w := &Watchdog{limit: limit, last: time.Now(), close: closeFlow}
	w.mu.Lock()
	w.timer = time.AfterFunc(limit, w.check)
	w.mu.Unlock()
	return w
}

func (w *Watchdog) check() {
	w.mu.Lock()
	if w.done {
		w.mu.Unlock()
		return
	}
	if remaining := w.limit - time.Since(w.last); remaining > 0 {
		w.timer.Reset(remaining)
		w.mu.Unlock()
		return
	}
	w.done = true
	closeFlow := w.close
	w.mu.Unlock()
	closeFlow()
}

// SetLimit starts a fresh idle period when the first direction finishes.
func (w *Watchdog) SetLimit(limit time.Duration) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.done || limit == w.limit {
		return
	}
	w.limit = limit
	w.last = time.Now()
	w.timer.Reset(limit)
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
		a.w.mu.Lock()
		a.w.last = time.Now()
		a.w.mu.Unlock()
	}
	return n, err
}
