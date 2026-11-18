package core

import (
	"context"
	"errors"
	"net"
	"slices"
	"strings"
	"time"
)

// Recovery policy. An initial connection (before the first Connected state of
// a run) is bounded: the first attempt plus initialRetryLimit retries, then
// Failed. Loss of an established session recovers indefinitely in cycles of
// cycleAttemptLimit attempts separated by Options.CyclePause, until success or
// an explicit stop. Native IKEv2 sessions keep the bounded policy throughout.
const (
	initialRetryLimit = 3
	cycleAttemptLimit = 10
)

// Status.ReconnectPhase values.
const (
	// PhaseAttempting: an attempt is scheduled (NextAttemptAt set) or running.
	PhaseAttempting = "attempting"
	// PhaseWaiting: a recovery cycle failed; the next cycle starts at NextAttemptAt.
	PhaseWaiting = "waiting"
)

// Status.KillSwitch values for a run that owns kill switch protection.
const (
	// KillSwitchActive: protection is installed and the tunnel carries traffic.
	KillSwitchActive = "active"
	// KillSwitchHolding: protection is installed while no tunnel carries
	// traffic (connecting, reconnecting, failed or stopping): traffic that the
	// routing policy does not send directly is blocked until connection or stop.
	KillSwitchHolding = "holding"
)

// ErrKillSwitchHeld rejects a Start that would replace a held kill switch
// with a session that does not keep it. Stop releases the protection first.
var ErrKillSwitchHeld = errors.New("kill_switch_held")

// ErrReconnectNotPending rejects ReconnectNow when no recovery wait is pending.
var ErrReconnectNotPending = errors.New("reconnect_not_pending")

// flapWindow: a connection shorter than this continues the previous recovery
// cycle instead of restarting it, so a flapping server cannot force a tight loop.
const flapWindow = time.Minute

// recovery is the per-run recovery bookkeeping. It is guarded by Engine.mu.
type recovery struct {
	cycles      bool // established-session loss recovers indefinitely
	established bool // Connected was reached in this run
	dropped     bool // the established session has been lost since Connected
	connectedAt time.Time
	attempt     int // attempts used in the initial budget or the current cycle
	cycle       int
	delay       time.Duration // last initial-phase backoff
}

// cycling reports whether failures are handled by the indefinite cycle policy.
func (r *recovery) cycling() bool { return r.cycles && r.established }

// connectedLocked records a successful connection for the recovery policy.
func (e *Engine) connectedLocked() {
	r := &e.recovery
	if !r.cycles {
		*r = recovery{}
		return
	}
	r.established = true
	r.dropped = false
	r.connectedAt = time.Now()
}

// recoverable reports whether err is followed by another attempt. Initial
// connections retry only retryable faults. After loss of an established
// session every failure is retried except those that need explicit recovery.
func (e *Engine) recoverable(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		// Context errors are terminal only after Stop; connect maps an
		// expired setup deadline to a retryable fault first.
		return false
	}
	if retryable(err) {
		return true
	}
	e.mu.Lock()
	cycling := e.recovery.cycling()
	e.mu.Unlock()
	return cycling && !requiresRecovery(err)
}

// closeFailure marks an error returned by a session's Close. Close owns
// network cleanup, so any such error, coded or not, ends the run.
type closeFailure struct{ error }

func (c closeFailure) Unwrap() error { return c.error }

// requiresRecovery marks faults after which the run must not continue on its
// own: failed cleanup or protection changes (codes ending in _run_recover),
// a failed session Close and a maintenance seal.
func requiresRecovery(err error) bool {
	return errors.Is(err, errMaintenanceSealed) || cleanupFailed(err)
}

// cleanupFailed marks failures that may leave network state behind. Kill
// switch protection is then retained until an explicit recover.
func cleanupFailed(err error) bool {
	var closed closeFailure
	if errors.As(err, &closed) {
		return true
	}
	var staged *stageError
	return errors.As(err, &staged) && strings.HasSuffix(staged.code, "_run_recover")
}

// drain discards a reconnect request that arrived for an earlier wait.
func drain(wake <-chan struct{}) {
	select {
	case <-wake:
	default:
	}
}

// linkFault marks failures of the installed tunnel itself. A persistent
// session cannot recover them in place and is closed and reopened instead.
func linkFault(err error) bool {
	var staged *stageError
	if !errors.As(err, &staged) {
		return false
	}
	switch staged.code {
	case "tunnel_adapter_lost", "dns_recovery_failed", "conflicting_dns_policy", "adapter_name_in_use":
		return true
	}
	return false
}

// cycleDelay is the backoff before attempt n (1-based) of a recovery cycle:
// base doubled per attempt and capped, e.g. 1, 2, 4, 8, 15, 15, ... seconds.
func cycleDelay(base, ceiling time.Duration, n int) time.Duration {
	d := base
	for i := 1; i < n && d < ceiling; i++ {
		d *= 2
	}
	return min(d, ceiling)
}

// scheduleLocked publishes the next recovery step for err and returns its
// delay. pause reports an inter-cycle wait. ok is false when the bounded
// budget is exhausted or the session is stopping.
func (e *Engine) scheduleLocked(err error) (delay time.Duration, pause, ok bool) {
	if e.status.State == Stopping {
		return 0, false, false
	}
	r := &e.recovery
	if r.cycling() {
		if !r.dropped {
			r.dropped = true
			// A fresh loss restarts the cycles; a short-lived connection
			// continues the previous cycle position (flapping).
			if r.cycle == 0 || time.Since(r.connectedAt) >= flapWindow {
				r.cycle, r.attempt = 1, 0
			}
		}
		if r.attempt >= cycleAttemptLimit {
			delay, pause = e.opts.CyclePause, true
			e.status.ReconnectAttempt, e.status.ReconnectLimit = 0, 0
			e.status.ReconnectPhase = PhaseWaiting
		} else {
			r.attempt++
			delay = cycleDelay(e.opts.RetryMin, e.opts.CycleRetryMax, r.attempt)
			e.status.ReconnectAttempt, e.status.ReconnectLimit = r.attempt, cycleAttemptLimit
			e.status.ReconnectPhase = PhaseAttempting
		}
		e.status.ReconnectCycle = r.cycle
	} else {
		if r.attempt >= initialRetryLimit {
			return 0, false, false
		}
		r.attempt++
		if r.attempt == 1 {
			r.delay = e.opts.RetryMin
		} else {
			r.delay = min(r.delay*2, e.opts.RetryMax)
		}
		delay = r.delay
		e.status.ReconnectAttempt, e.status.ReconnectLimit = r.attempt, initialRetryLimit
		e.status.ReconnectPhase = PhaseAttempting
	}
	// Whole seconds, rounded up: the attempt never starts before this time.
	next := time.Now().Add(delay).UTC()
	if rounded := next.Truncate(time.Second); rounded.Before(next) {
		next = rounded.Add(time.Second)
	}
	e.status.NextAttemptAt = next
	e.transitionLocked(Reconnecting, err)
	// The state/error can be unchanged between retries; still publish progress.
	if pause {
		e.emitLocked("reconnect_wait", "Recovery cycle failed; waiting before the next cycle")
	} else {
		e.emitLocked("reconnect_attempt", "Reconnect attempt scheduled")
	}
	return delay, pause, true
}

// awaitAttempt schedules the next recovery attempt after err and waits for it.
// It returns nil when the attempt should run now, err when the bounded budget
// is exhausted, or the context error after Stop.
func (e *Engine) awaitAttempt(ctx context.Context, err error) error {
	e.mu.Lock()
	// Discard requests for an earlier wait before this one is published, so a
	// reconnect_now accepted for it is never lost.
	drain(e.wake)
	delay, pause, ok := e.scheduleLocked(err)
	wake := e.wake
	e.mu.Unlock()
	if !ok {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	if err := e.sleep(ctx, delay, wake); err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.status.NextAttemptAt = time.Time{}
	if pause {
		r := &e.recovery
		r.cycle++
		r.attempt = 1
		e.status.ReconnectCycle = r.cycle
		e.status.ReconnectAttempt, e.status.ReconnectLimit = 1, cycleAttemptLimit
		e.status.ReconnectPhase = PhaseAttempting
		e.emitLocked("reconnect_attempt", "Recovery cycle started")
	}
	return nil
}

// sleep waits for delay. A reconnect request, a changed set of local network
// interfaces or a detected resume from sleep ends the wait early.
func (e *Engine) sleep(ctx context.Context, delay time.Duration, wake <-chan struct{}) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	poll := time.NewTicker(e.pollEvery)
	defer poll.Stop()
	network := e.network()
	last := time.Now()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return nil
		case <-wake:
			e.report("reconnect_requested", "Reconnect requested; retrying now")
			return nil
		case <-poll.C:
			now := time.Now()
			if resumed(last, now) {
				e.report("resume_detected", "Resume detected; retrying now")
				return nil
			}
			last = now
			if current := e.network(); current != network {
				e.report("network_changed", "Network changed; retrying now")
				return nil
			}
		}
	}
}

// ReconnectNow ends a pending recovery wait, or restarts the bounded initial
// attempts of a failed session whose kill switch is held. It never cancels an
// attempt in progress.
func (e *Engine) ReconnectNow() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.active || e.wake == nil || !(e.holding || e.status.State == Reconnecting && !e.status.NextAttemptAt.IsZero()) {
		return ErrReconnectNotPending
	}
	select {
	case e.wake <- struct{}{}:
	default:
	}
	return nil
}

// interfaceIdentity summarizes local network interfaces other than the tunnel.
// It only detects changes; it carries no addresses outside the process.
func interfaceIdentity(tunnel string) string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	var parts []string
	for _, i := range interfaces {
		if i.Name == tunnel || i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, _ := i.Addrs()
		entry := []string{i.Name}
		for _, a := range addresses {
			entry = append(entry, a.String())
		}
		slices.Sort(entry[1:])
		parts = append(parts, strings.Join(entry, ","))
	}
	slices.Sort(parts)
	return strings.Join(parts, ";")
}
